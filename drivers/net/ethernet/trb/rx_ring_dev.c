#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/miscdevice.h>
#include <linux/eventfd.h>
#include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <net/page_pool/types.h>
#include <net/page_pool/helpers.h>
#include <net/netmem.h>
#include <net/net_namespace.h>
#include <net/tcp.h>
#include <net/trb.h>
#include <linux/poison.h>
#include <linux/highmem.h>
#include <linux/mutex.h>
#include <linux/list.h>

#define META_PAGES 3
#define VM_TOTAL_PAGES 256
#define DEV_NAME "trb_dev"

/* Ring capacity must be powers of two for mask-based indexing */
#define DESC_CAP 64     /* kernel -> user descriptors */
#define FILL_CAP 256     /* user -> kernel buf_id ring */  /* should the size equal desc size or num_buffers */

/* Switch to pp_frag for sub_page buffers */
#define BUF_SIZE PAGE_SIZE

#define TRB_DESC_F_CLOSE 0x1


struct trb_efd_req {
	__u16 qid;
	__u16 reserved;
	__s32 efd_fd;
};

#define IOCTL_REGISTER_EFD _IOW('m', 1, struct trb_efd_req)

#define IOCTL_TEST_PRODUCE _IOW('m', 2, u32)
#define IOCTL_SET_NUM_QS _IOW('m', 3, __u16)
#define IOCTL_TRB_CONFIG _IOW('m', 4, struct trb_cfg_req)

struct trb_cfg_req {
	char ifname[IFNAMSIZ];
	__u16 num_qs;
	__u16 dport;
	__u8 enable;
	__u8 fs_type;
	__u16 reserved;
};

extern int mlx5e_trb_configure(struct net_device *netdev, bool enable,
			       unsigned int num_channels, u8 trb_fs_type,
			       u16 trb_dport, struct trb_dev *trb_dev);

struct rx_hdr_qoff {
	__u64 desc_off;
	__u64 rr_off;
	__u64 pool_off;
};

struct rx_ring_hdr {
	__u16 num_qs;
	__u16 reserved;
	__u32 doorbell;
	struct rx_hdr_qoff q[];
};

struct trb_desc {
	__u64 conn_id; /* app-provided connection id from accept5() */
	__u32 buf_id; /* index into payload buffers (0 ... buf_cap - 1) */
	__u32 len;    /* valid bytes starting at off */
	__u32 off;    /* byte offset within the buffer */
	__u32 flags;  /* future use */
};

struct descriptor_ring {
	__u32 prod;
	__u32 con;
	__u32 desc_cap;
	__u64 pool_size;
	__u32 buf_cap;
	__u32 buf_size;
	struct trb_desc descs[];
};

struct recycle_ring {
    __u32 prod;
    __u32 con;
    __u32 cap;
    __u32 mask;
    __u32 entries[];
};

struct trb_free_entry {
	struct page *page;
	__u32 page_ix;
};

struct trb_free_ring {
	__u32 prod;
	__u32 con;
	__u32 cap; /* number of TRB pages tracked */
	struct trb_free_entry entries[];
};

/* Kernel private state */

struct buf_map_entry {
	struct page *page;
	dma_addr_t dma_base;
	__u32 page_ix;
	__u32 inflight;
};

struct queue_ctx;

struct trb_dev {
    
    struct miscdevice misc;
    u16 total_qs;
    u16 qctx_cap;
    struct queue_ctx **qctx_by_rq;
    struct mutex qctx_lock;

    /* Vmalloc-ed meta root + per-queue ring pointer tables */
    void *meta_base;
    size_t meta_bytes;
    struct rx_ring_hdr *hdr;
    struct descriptor_ring **dr_by_qid;
    struct recycle_ring **rr_by_qid;
	atomic_t mmap_cnt;
	struct list_head pending_qctx;

    /* Payload backing via page_pool */

};

struct queue_ctx {
	struct trb_dev *dev;
	struct eventfd_ctx *efd;
	u16 qid;
	struct list_head pending_node;
	bool pending_free;

	/* Per-queue datapath state (currently not wired; shape only). */
	struct descriptor_ring *dr;
	struct recycle_ring *rr;
	struct trb_free_ring *free_ring;
	struct page_pool *pp;
	struct page **pages;
	struct buf_map_entry *bufs;
};

static bool trb_dev_ready;
static int build_meta_and_userspace_pool(struct trb_dev *d);

static void trb_qctx_free(struct queue_ctx *qctx)
{
	u32 i;

	if (!qctx)
		return;

	if (qctx->efd)
		eventfd_ctx_put(qctx->efd);

	if (qctx->pages && qctx->pp && qctx->free_ring) {
		for (i = 0; i < qctx->free_ring->cap; i++) {
			if (qctx->pages[i])
				page_pool_put_page(qctx->pp, qctx->pages[i], 0, true);
		}
	}

	kfree(qctx->bufs);
	kfree(qctx->pages);
	kvfree(qctx->free_ring);
	if (qctx->pp)
		page_pool_destroy(qctx->pp);
	kfree(qctx);
}

static void trb_dev_destroy(struct trb_dev *dev)
{
	struct queue_ctx *qctx, *tmp;

	if (!dev)
		return;

	list_for_each_entry_safe(qctx, tmp, &dev->pending_qctx, pending_node) {
		list_del_init(&qctx->pending_node);
		trb_qctx_free(qctx);
	}
	kfree(dev->qctx_by_rq);

	kfree(dev->dr_by_qid);
	kfree(dev->rr_by_qid);
	vfree(dev->meta_base);
	kfree(dev);
}

static int trb_set_num_qs(struct trb_dev *dev, __u16 nqs)
{
	struct queue_ctx **tbl;
	int ret;

	if (!dev || !nqs)
		return -EINVAL;

	mutex_lock(&dev->qctx_lock);
	if (dev->qctx_by_rq) {
		mutex_unlock(&dev->qctx_lock);
		return -EBUSY;
	}

	tbl = kcalloc(nqs, sizeof(*tbl), GFP_KERNEL);
	if (!tbl) {
		mutex_unlock(&dev->qctx_lock);
		return -ENOMEM;
	}

	dev->qctx_by_rq = tbl;
	dev->qctx_cap = nqs;
	dev->total_qs = 0;
	mutex_unlock(&dev->qctx_lock);

	ret = build_meta_and_userspace_pool(dev);
	if (ret) {
		mutex_lock(&dev->qctx_lock);
		kfree(dev->qctx_by_rq);
		dev->qctx_by_rq = NULL;
		dev->qctx_cap = 0;
		dev->total_qs = 0;
		mutex_unlock(&dev->qctx_lock);
		return ret;
	}

	trb_dev_ready = true;
	return 0;
}

static int trb_qctx_track_add(struct trb_dev *dev, u16 qid,
			      struct queue_ctx *ctx)
{
	if (!dev || !ctx)
		return -EINVAL;

	mutex_lock(&dev->qctx_lock);
	if (!dev->qctx_by_rq || qid >= dev->qctx_cap) {
		mutex_unlock(&dev->qctx_lock);
		return -ERANGE;
	}

	if (dev->qctx_by_rq[qid]) {
		mutex_unlock(&dev->qctx_lock);
		return -EEXIST;
	}

	dev->qctx_by_rq[qid] = ctx;
	dev->total_qs++;
	mutex_unlock(&dev->qctx_lock);
	return 0;
}

static void trb_qctx_track_del(struct trb_dev *dev, u16 qid)
{
	if (!dev)
		return;

	mutex_lock(&dev->qctx_lock);
	if (dev->qctx_by_rq && qid < dev->qctx_cap && dev->qctx_by_rq[qid]) {
		dev->qctx_by_rq[qid] = NULL;
		if (dev->total_qs)
			dev->total_qs--;
	}
	mutex_unlock(&dev->qctx_lock);
}

void trb_unregister_qctx(struct queue_ctx *qctx)
{
	struct trb_dev *dev;
	u16 qid, idx;

	if (!qctx || !qctx->dev)
		return;

	dev = qctx->dev;
	qid = qctx->qid;
	if (!qid)
		goto out_free;
	idx = qid - 1;

	mutex_lock(&dev->qctx_lock);
	if (dev->qctx_by_rq && idx < dev->qctx_cap &&
	    dev->qctx_by_rq[idx] == qctx) {
		dev->qctx_by_rq[idx] = NULL;
		if (dev->total_qs)
			dev->total_qs--;
	}
	mutex_unlock(&dev->qctx_lock);

out_free:
	mutex_lock(&dev->qctx_lock);
	if (atomic_read(&dev->mmap_cnt) > 0) {
		if (!qctx->pending_free) {
			qctx->pending_free = true;
			list_add_tail(&qctx->pending_node, &dev->pending_qctx);
		}
		mutex_unlock(&dev->qctx_lock);
		return;
	}
	mutex_unlock(&dev->qctx_lock);

	trb_qctx_free(qctx);
}
EXPORT_SYMBOL_GPL(trb_unregister_qctx);

static int build_meta_and_userspace_pool(struct trb_dev *d);

static void trb_vm_close(struct vm_area_struct *vma)
{
	struct trb_dev *dev = vma->vm_private_data;
	struct queue_ctx *qctx, *tmp;

	if (!dev)
		return;
	if (atomic_dec_return(&dev->mmap_cnt) != 0)
		return;

	mutex_lock(&dev->qctx_lock);
	list_for_each_entry_safe(qctx, tmp, &dev->pending_qctx, pending_node) {
		list_del_init(&qctx->pending_node);
		mutex_unlock(&dev->qctx_lock);
		trb_qctx_free(qctx);
		mutex_lock(&dev->qctx_lock);
	}
	mutex_unlock(&dev->qctx_lock);
}

static const struct vm_operations_struct trb_vm_ops = {
	.close = trb_vm_close,
};

static int trb_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct trb_dev *d = file->private_data;
	unsigned long len = vma->vm_end - vma->vm_start;
	unsigned long need;
	unsigned long off;
	unsigned long cursor;
	struct page *pg;
	u16 qid;
	int ret;

	if (!d || !d->meta_base || !d->hdr)
		return -ENODEV;
	vma->vm_ops = &trb_vm_ops;
	vma->vm_private_data = d;
	atomic_inc(&d->mmap_cnt);

	need = d->meta_bytes;
	mutex_lock(&d->qctx_lock);
	cursor = d->hdr->q[0].pool_off;
	if (d->qctx_by_rq) {
		for (qid = 0; qid < d->qctx_cap; qid++) {
			struct queue_ctx *qctx = d->qctx_by_rq[qid];
			unsigned long qbytes;

			if (!qctx || !qctx->free_ring)
				continue;

			d->hdr->q[qid].pool_off = cursor;
			qbytes = (unsigned long)qctx->free_ring->cap * PAGE_SIZE;
			cursor += qbytes;
		}
	}
	if (cursor > need)
		need = cursor;
	mutex_unlock(&d->qctx_lock);

	if (len < need)
		return -EINVAL;

	for (off = 0; off < d->meta_bytes; off += PAGE_SIZE) {
		pg = vmalloc_to_page((u8 *)d->meta_base + off);
		if (!pg)
			return -EFAULT;

		ret = vm_insert_page(vma, vma->vm_start + off, pg);
		if (ret)
			return ret;
	}

	mutex_lock(&d->qctx_lock);
	if (d->qctx_by_rq) {
		for (qid = 0; qid < d->qctx_cap; qid++) {
			struct queue_ctx *qctx = d->qctx_by_rq[qid];
			unsigned long uaddr;
			u32 i;

			if (!qctx || !qctx->pages || !qctx->free_ring)
				continue;

			uaddr = vma->vm_start + d->hdr->q[qid].pool_off;
			for (i = 0; i < qctx->free_ring->cap; i++, uaddr += PAGE_SIZE) {
				pg = qctx->pages[i];
				if (!pg) {
					mutex_unlock(&d->qctx_lock);
					return -EFAULT;
				}

				ret = vm_insert_page(vma, uaddr, pg);
				if (ret) {
					mutex_unlock(&d->qctx_lock);
					return ret;
				}
			}
		}
	}
	mutex_unlock(&d->qctx_lock);

	return 0;
}

static inline bool rr_pop(struct recycle_ring *rr, __u32 *out)
{
    __u32 prod = smp_load_acquire(&rr->prod);
    __u32 con = READ_ONCE(rr->con);
    if(prod == con)
        return false;
    __u32 idx = con & rr->mask;

    *out = rr->entries[idx];
    smp_store_release(&rr->con, con + 1);
    return true;
}

static inline void rr_push(struct recycle_ring *rr, __u32 v)
{
    __u32 prod = READ_ONCE(rr->prod);
    __u32 idx = prod & rr->mask;

    rr->entries[idx] = v;
    smp_store_release(&rr->prod, prod + 1);
}

int trb_free_ring_return_ctx(struct queue_ctx *qctx,
			     struct page *page, __u32 idx)
{
	struct trb_free_ring *ring;
	struct trb_free_entry *entry;
	u32 prod;

	if (!qctx || !qctx->free_ring || !page)
		return -EINVAL;

	ring = qctx->free_ring;
	prod = READ_ONCE(ring->prod);
	if (prod - READ_ONCE(ring->con) >= ring->cap)
		return -ENOSPC;

	entry = &ring->entries[prod & (ring->cap - 1)];
	entry->page = page;
	entry->page_ix = idx;
	smp_store_release(&ring->prod, prod + 1);
	return 0;
}
EXPORT_SYMBOL_GPL(trb_free_ring_return_ctx);

static inline void trb_buf_put_page(struct queue_ctx *qctx, __u32 buf_id)
{
	struct buf_map_entry *b;
	long ret;

	if (!qctx || !qctx->bufs || !qctx->pp)
		return;
	b = &qctx->bufs[buf_id];

	ret = page_pool_unref_page(b->page, 1);
	if (ret) {
		pr_warn("TRB put path=drain_rr page_ix=%u ref_after=%ld to_free_ring=0\n",
			b->page_ix, ret);
		return;
	}

	if (!trb_free_ring_return_ctx(qctx, b->page, b->page_ix)) {
		pr_warn("TRB put path=drain_rr page_ix=%u ref_after=0 to_free_ring=1\n",
			b->page_ix);
		return;
	}

	pr_warn("TRB put path=drain_rr page_ix=%u ref_after=0 to_free_ring=0\n",
		b->page_ix);
	page_pool_put_unrefed_page(qctx->pp, b->page, -1, false);
}

/* Placeholder: assume userspace provides buf_ids to recycle */
static void drain_rr(struct queue_ctx *qctx)
{
	struct recycle_ring *rr;
	struct descriptor_ring *dr;
	__u32 buf_id;

	if (!qctx)
		return;
	rr = qctx->rr;
	dr = qctx->dr;

	if (!rr || !dr || !qctx->bufs)
		return;

	while (rr_pop(rr, &buf_id)) {
		if (buf_id >= dr->buf_cap)
			continue;
		if (!qctx->bufs[buf_id].inflight)
			continue;

		qctx->bufs[buf_id].inflight--;
		trb_buf_put_page(qctx, buf_id);
	}
}
/* This should also obviously take a queue context when hooked up with multiple cores */
struct page_pool *trb_register_pp(struct page_pool_params *pp, size_t buf_size,
				  u16 rq_ix, struct trb_dev *dev,
				  struct queue_ctx **out_qctx)
{
	struct queue_ctx *ctx;
	struct descriptor_ring *dr;
	u16 qidx;
	struct page_pool *pool;
	struct trb_free_ring *free_ring = NULL;
	struct page *pg;
	size_t bufs_per_page;
	size_t total_bufs;
	size_t free_ring_bytes;
	size_t i, j, bidx;
	unsigned long page_bytes;
	int err = -EINVAL;

	if (!pp || !buf_size || !out_qctx)
		return ERR_PTR(-EINVAL);
	*out_qctx = NULL;

	if (!trb_dev_ready || !dev)
		return ERR_PTR(-EINVAL);
	if (!rq_ix)
		return ERR_PTR(-EINVAL);

	qidx = rq_ix - 1;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	ctx->dev = dev;
	ctx->efd = NULL;
	ctx->qid = rq_ix;
	INIT_LIST_HEAD(&ctx->pending_node);
	ctx->pending_free = false;
	ctx->dr = (dev->dr_by_qid && qidx < dev->qctx_cap) ?
		  dev->dr_by_qid[qidx] : NULL;
	ctx->rr = (dev->rr_by_qid && qidx < dev->qctx_cap) ?
		  dev->rr_by_qid[qidx] : NULL;
	ctx->pp = NULL;
	ctx->pages = NULL;
	ctx->bufs = NULL;
	ctx->free_ring = NULL;
	if (!ctx->dr || !ctx->rr)
		goto err_free_ctx_only;
	err = trb_qctx_track_add(dev, qidx, ctx);
	if (err) {
		kfree(ctx);
		return ERR_PTR(err);
	}

	pool = page_pool_create(pp);
	if (IS_ERR(pool)) {
		err = PTR_ERR(pool);
		goto err_free_ctx;
	}

	page_bytes = PAGE_SIZE << pp->order;
	bufs_per_page = DIV_ROUND_UP(page_bytes, buf_size);
	total_bufs = (size_t)pp->pool_size * bufs_per_page;

	ctx->pp = pool;

	ctx->pages = kcalloc(pp->pool_size, sizeof(*ctx->pages), GFP_KERNEL);
	if (!ctx->pages) {
		err = -ENOMEM;
		goto err_destroy_pool;
	}

	ctx->bufs = kcalloc(total_bufs, sizeof(*ctx->bufs), GFP_KERNEL);
	if (!ctx->bufs) {
		err = -ENOMEM;
		goto err_free_pages;
	}

	for (i = 0; i < pp->pool_size; i++) {
		pg = page_pool_dev_alloc_pages(pool);
		if (!pg) {
			err = -ENOMEM;
			goto err_release_pages;
		}

		ctx->pages[i] = pg;

		for (j = 0; j < bufs_per_page; j++) {
			bidx = i * bufs_per_page + j;
			ctx->bufs[bidx].page = pg;
			ctx->bufs[bidx].dma_base = (dma_addr_t)(j * buf_size);
			ctx->bufs[bidx].page_ix = i;
			ctx->bufs[bidx].inflight = 0;
		}
	}

	free_ring_bytes = struct_size(free_ring, entries, pp->pool_size);
	free_ring = kvzalloc(free_ring_bytes, GFP_KERNEL);
	if (!free_ring) {
		err = -ENOMEM;
		goto err_release_pages;
	}

	free_ring->con = 0;
	free_ring->prod = pp->pool_size;
	free_ring->cap = pp->pool_size;
	for (i = 0; i < pp->pool_size; i++) {
		free_ring->entries[i].page = ctx->pages[i];
		free_ring->entries[i].page_ix = i;
	}
	ctx->free_ring = free_ring;

	dr = ctx->dr;
	WRITE_ONCE(dr->prod, 0);
	WRITE_ONCE(dr->con, 0);
	dr->buf_size = buf_size;
	dr->buf_cap = total_bufs;
	dr->pool_size = (__u64)total_bufs * buf_size;
	*out_qctx = ctx;

	return pool;

err_release_pages:
	while (i--) {
		if (ctx->pages[i]) {
			page_pool_put_page(pool, ctx->pages[i], 0, true);
			ctx->pages[i] = NULL;
		}
	}
	kvfree(free_ring);
	kfree(ctx->bufs);
	ctx->bufs = NULL;
err_free_pages:
	kfree(ctx->pages);
	ctx->pages = NULL;
err_destroy_pool:
	page_pool_destroy(pool);
err_free_ctx:
	trb_qctx_track_del(dev, qidx);
	kfree(ctx);
	return ERR_PTR(err);
err_free_ctx_only:
	kfree(ctx);
	return ERR_PTR(-EINVAL);
}

static int build_meta_and_userspace_pool(struct trb_dev *d)
{
	size_t hdr_sz, dr_bytes, rr_bytes, need_bytes, meta_bytes;
	size_t dr_region_off, rr_region_off, pool_base_off;
	struct rx_ring_hdr *hdr;
	struct descriptor_ring *dr;
	struct recycle_ring *rr;
	u16 nqs;
	u16 qid;
	void *base;

	if (!d)
		return -EINVAL;
	nqs = d->qctx_cap;
	if (!nqs)
		return -EINVAL;

	/* Layout:
	 * [ rx_ring_hdr + q[nqs] ]
	 * [ descriptor_ring for q0 ][ descriptor_ring for q1 ] ... [ q(n-1) ]
	 * [ recycle_ring    for q0 ][ recycle_ring    for q1 ] ... [ q(n-1) ]
	 * [ pool region base for q0 ][ pool for q1 ] ... [ q(n-1) ] (offsets filled later)
	 */
	hdr_sz = sizeof(struct rx_ring_hdr) + sizeof(struct rx_hdr_qoff) * nqs;
	dr_bytes = sizeof(struct descriptor_ring) + sizeof(struct trb_desc) * DESC_CAP;
	rr_bytes = sizeof(struct recycle_ring) + sizeof(__u32) * FILL_CAP;
	dr_region_off = ALIGN(hdr_sz, 64);
	rr_region_off = ALIGN(dr_region_off + dr_bytes * nqs, 64);
	need_bytes = ALIGN(rr_region_off + rr_bytes * nqs, PAGE_SIZE);

	/* For now reserve metadata only; per-queue pool offsets point to common pool base
	 * and can be updated per queue later when pool layout is split.
	 */
	meta_bytes = META_PAGES * PAGE_SIZE;
	if (meta_bytes < need_bytes)
		meta_bytes = need_bytes;
	pool_base_off = ALIGN(meta_bytes, PAGE_SIZE);

	/* Rebuild-safe */
	if (d->meta_base) {
		vfree(d->meta_base);
		d->meta_base = NULL;
		d->meta_bytes = 0;
	}
	kfree(d->dr_by_qid);
	kfree(d->rr_by_qid);
	d->dr_by_qid = NULL;
	d->rr_by_qid = NULL;

	base = vzalloc(meta_bytes);
	if (!base)
		return -ENOMEM;

	d->dr_by_qid = kcalloc(nqs, sizeof(*d->dr_by_qid), GFP_KERNEL);
	d->rr_by_qid = kcalloc(nqs, sizeof(*d->rr_by_qid), GFP_KERNEL);
	if (!d->dr_by_qid || !d->rr_by_qid) {
		kfree(d->dr_by_qid);
		kfree(d->rr_by_qid);
		d->dr_by_qid = NULL;
		d->rr_by_qid = NULL;
		vfree(base);
		return -ENOMEM;
	}

	d->meta_base = base;
	d->meta_bytes = meta_bytes;

	hdr = d->hdr = (struct rx_ring_hdr *)base;
	hdr->num_qs = nqs;
	hdr->reserved = 0;
	WRITE_ONCE(hdr->doorbell, 0);

	for (qid = 0; qid < nqs; qid++) {
		hdr->q[qid].desc_off = dr_region_off + (u64)qid * dr_bytes;
		hdr->q[qid].rr_off = rr_region_off + (u64)qid * rr_bytes;
		hdr->q[qid].pool_off = 0;

		dr = (struct descriptor_ring *)((__u8 *)base + hdr->q[qid].desc_off);
		d->dr_by_qid[qid] = dr;
		WRITE_ONCE(dr->prod, 0);
		WRITE_ONCE(dr->con, 0);
		dr->desc_cap = DESC_CAP;
		dr->pool_size = 0;
		dr->buf_cap = 0;
		dr->buf_size = 0;

		rr = (struct recycle_ring *)((__u8 *)base + hdr->q[qid].rr_off);
		d->rr_by_qid[qid] = rr;
		WRITE_ONCE(rr->prod, 0);
		WRITE_ONCE(rr->con, 0);
		rr->cap = FILL_CAP;
		rr->mask = FILL_CAP - 1;
	}

	/* Base cursor for mmap-time pool layout assignment. */
	hdr->q[0].pool_off = pool_base_off;

	return 0;
}

/* test and publish functions here */

static int trb_publish_and_signal(struct queue_ctx *q, u32 new_prod)
{
    struct rx_ring_hdr *hdr = q->dev->hdr;
    struct descriptor_ring *dr = q->dr;
    bool was_empty = READ_ONCE(dr->prod) == READ_ONCE(dr->con);

    smp_store_release(&dr->prod, new_prod);

    if (was_empty && likely(q->efd)) {
        WRITE_ONCE(hdr->doorbell, READ_ONCE(hdr->doorbell) + 1);
        eventfd_signal(q->efd);
    }
    return 0;
}

static long trb_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct trb_dev *dev = file->private_data;
	struct queue_ctx *q = NULL;
	struct eventfd_ctx *efd;

	if (!dev)
		return -ENODEV;

	switch (cmd) {
	case IOCTL_SET_NUM_QS: {
		__u16 nqs;

		if (copy_from_user(&nqs, (void __user *)arg, sizeof(nqs)))
			return -EFAULT;
		return trb_set_num_qs(dev, nqs);
	}
	case IOCTL_REGISTER_EFD: {
		struct trb_efd_req req;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;

		mutex_lock(&dev->qctx_lock);
		if (!dev->qctx_by_rq || req.qid >= dev->qctx_cap) {
			mutex_unlock(&dev->qctx_lock);
			return -EINVAL;
		}
		q = dev->qctx_by_rq[req.qid];
		if (!q) {
			mutex_unlock(&dev->qctx_lock);
			return -ENODEV;
		}
		mutex_unlock(&dev->qctx_lock);

		efd = eventfd_ctx_fdget(req.efd_fd);
		if (IS_ERR(efd))
			return PTR_ERR(efd);

		if (q->efd)
			eventfd_ctx_put(q->efd);
		q->efd = efd;
		return 0;
	}
	case IOCTL_TEST_PRODUCE: {
		return -EOPNOTSUPP;
	}
	case IOCTL_TRB_CONFIG: {
		struct trb_cfg_req req;
		struct net_device *netdev;
		unsigned int num_channels;
		int ret;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;
		req.ifname[IFNAMSIZ - 1] = '\0';

		if (!req.ifname[0] || !req.num_qs)
			return -EINVAL;

		netdev = dev_get_by_name(&init_net, req.ifname);
		if (!netdev)
			return -ENODEV;

		/* userspace passes worker queues (n); driver needs q0 + n */
		num_channels = req.num_qs + 1;

		rtnl_lock();
		ret = mlx5e_trb_configure(netdev, !!req.enable, num_channels,
					  req.fs_type, req.dport, dev);
		rtnl_unlock();
		dev_put(netdev);

		return ret;
	}
	default:
		return -ENOIOCTLCMD;
	}
}



static int trb_open(struct inode *ino, struct file *file)
{
	struct trb_dev *dev;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	mutex_init(&dev->qctx_lock);
	atomic_set(&dev->mmap_cnt, 0);
	INIT_LIST_HEAD(&dev->pending_qctx);
	file->private_data = dev;
	return 0;
}

static int trb_release(struct inode *ino, struct file *file)
{
	struct trb_dev *dev = file->private_data;

	if (dev && READ_ONCE(dev->total_qs))
		return -EBUSY;

	trb_dev_destroy(dev);
	file->private_data = NULL;
	return 0;
}

static const struct file_operations trb_fops = {
    .owner = THIS_MODULE,
    .mmap = trb_mmap,
    .open = trb_open,
    .release = trb_release,
    .unlocked_ioctl = trb_ioctl,
};

static struct miscdevice trb_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = DEV_NAME,
	.fops = &trb_fops,
	.mode = 0666,
};

static int __init trb_init(void)
{
    int ret;

    trb_dev_ready = false;

    ret = misc_register(&trb_misc);
    if (ret) {
        return ret;
    }
    pr_info("%s: registered (deferred init)", DEV_NAME);
	return 0;
}

static struct page *trb_free_ring_alloc(struct queue_ctx *qctx, __u32 *idx)
{
	struct trb_dev *dev;
	struct trb_free_ring *ring;
	struct trb_free_entry *entry;
	u32 con;

	if (!qctx || !idx)
		return NULL;
	dev = qctx->dev;
	if (!dev || !qctx->free_ring)
		return NULL;

	ring = qctx->free_ring;
	con = READ_ONCE(ring->con);
	if (con == READ_ONCE(ring->prod))
		return NULL;

	entry = &ring->entries[con & (ring->cap - 1)];
	*idx = entry->page_ix;
	/* pr_warn("TRB alloc: idx=%u page=%px con=%u prod=%u\n",
	 *	*idx, entry->page, con, READ_ONCE(ring->prod));
	 */
	smp_store_release(&ring->con, con + 1);
	return entry->page;
}

struct page* trb_page_pool_alloc(struct queue_ctx *qctx, __u32 *idx)
{
	if (!qctx || !idx)
		return NULL;

	if (qctx->rr)
		drain_rr(qctx);

	return trb_free_ring_alloc(qctx, idx);
}
EXPORT_SYMBOL_GPL(trb_page_pool_alloc);

static inline bool trb_is_pp_page(struct page *page)
{
	return (page->pp_magic & ~0x3UL) == PP_SIGNATURE;
}

static int trb_buf_from_region(struct queue_ctx *qctx, u32 page_ix, struct page *page,
			       u32 payload_start, u32 len,
			       u32 *buf_id, u32 *off, u32 *seg_len)
{
	struct descriptor_ring *dr;
	struct trb_free_ring *fr;
	u32 bufs_per_page;
	u32 page_bytes;
	u32 buf_idx_in_page;

	if (!qctx || !page || !len)
		return -EINVAL;
	dr = qctx->dr;
	fr = qctx->free_ring;
	if (!dr || !fr || !dr->buf_size)
		return -EINVAL;

	page_bytes = PAGE_SIZE << compound_order(page);
	bufs_per_page = DIV_ROUND_UP(page_bytes, dr->buf_size);

	if (page_ix >= fr->cap)
		return -EINVAL;
	if (payload_start >= page_bytes)
		return -EINVAL;

	buf_idx_in_page = payload_start / dr->buf_size;
	*buf_id = page_ix * bufs_per_page + buf_idx_in_page;
	*off = payload_start % dr->buf_size;
	*seg_len = min_t(u32, len, dr->buf_size - *off);
	return 0;
}

static int trb_count_segments_pp_one(struct sk_buff *skb)
{
	struct skb_shared_info *sh;
	struct page *head_page;
	u32 head_len;
	struct sk_buff *frag_skb;
	int count = 0;
	int i;

	if (!skb)
		return 0;

	sh = skb_shinfo(skb);
	head_page = virt_to_head_page(skb->data);
	head_len = skb_headlen(skb);

	if (head_len && trb_is_pp_page(head_page))
		count++;

	for (i = 0; i < sh->nr_frags; i++) {
		if (trb_is_pp_page(skb_frag_page(&sh->frags[i])))
			count++;
	}

	skb_walk_frags(skb, frag_skb)
		count += trb_count_segments_pp_one(frag_skb);

	return count;
}

static int trb_count_segments_pp(struct sk_buff *skb)
{
	return trb_count_segments_pp_one(skb);
}

static void trb_emit_close_desc(struct queue_ctx *qctx, u32 prod, u64 conn_id)
{
	struct trb_desc *td;

	td = &qctx->dr->descs[prod & (qctx->dr->desc_cap - 1)];
	WRITE_ONCE(td->conn_id, conn_id);
	WRITE_ONCE(td->buf_id, 0);
	WRITE_ONCE(td->len, 0);
	WRITE_ONCE(td->off, 0);
	WRITE_ONCE(td->flags, TRB_DESC_F_CLOSE);
}

static int trb_emit_segments_pp_one(struct queue_ctx *qctx, struct sk_buff *skb,
				    u32 prod, int *seg_idx, u64 conn_id)
{
	struct descriptor_ring *dr;
	struct skb_shared_info *sh;
	struct page *head_page;
	u32 head_len;
	struct trb_desc *td;
	struct sk_buff *frag_skb;
	int i;

	if (!qctx || !qctx->dr || !qctx->bufs)
		return -EINVAL;
	dr = qctx->dr;

	sh = skb_shinfo(skb);
	head_page = virt_to_head_page(skb->data);
	head_len = skb_headlen(skb);

	if (head_len && trb_is_pp_page(head_page)) {
		u32 buf_id, off, seg_len, payload_start, page_ix;

		payload_start = (u32)((unsigned long)skb->data -
				      (unsigned long)page_address(head_page));
		page_ix = READ_ONCE(skb->trb_head_page_ix);
		if (trb_buf_from_region(qctx, page_ix, head_page, payload_start,
					head_len, &buf_id, &off, &seg_len))
			return -EINVAL;
		pr_warn("TRB emit head: page_ix=%u buf_id=%u off=%u len=%u payload_start=%u buf_size=%u\n",
			page_ix, buf_id, off, seg_len, payload_start, dr->buf_size);

			td = &dr->descs[(prod + *seg_idx) & (dr->desc_cap - 1)];
				WRITE_ONCE(td->conn_id, conn_id);
				WRITE_ONCE(td->buf_id, buf_id);
				WRITE_ONCE(td->len, seg_len);
				WRITE_ONCE(td->off, off);
				WRITE_ONCE(td->flags, 0);
			pr_warn("TRB emit store head: buf_id=%u skb=%px users=%d active_ext=%u ext=%px trb_pkt=%u trb_head_ix=%u\n",
				buf_id, skb, refcount_read(&skb->users),
				skb->active_extensions, skb->extensions,
				skb->trb_pkt, skb->trb_head_page_ix);
			page_pool_ref_page(qctx->bufs[buf_id].page);
			qctx->bufs[buf_id].inflight++;
			(*seg_idx)++;
		}

	for (i = 0; i < sh->nr_frags; i++) {
		struct page *fp;
		u32 buf_id, off, seg_len, payload_start, page_ix;

		fp = skb_frag_page(&sh->frags[i]);
		if (!trb_is_pp_page(fp))
			continue;

		payload_start = skb_frag_off(&sh->frags[i]);
		page_ix = READ_ONCE(sh->trb_page_ix[i]);
		if (trb_buf_from_region(qctx, page_ix, fp, payload_start,
					skb_frag_size(&sh->frags[i]),
					&buf_id, &off, &seg_len))
			return -EINVAL;
		pr_warn("TRB emit frag: page_ix=%u buf_id=%u off=%u len=%u payload_start=%u buf_size=%u\n",
			page_ix, buf_id, off, seg_len, payload_start, dr->buf_size);

			td = &dr->descs[(prod + *seg_idx) & (dr->desc_cap - 1)];
				WRITE_ONCE(td->conn_id, conn_id);
				WRITE_ONCE(td->buf_id, buf_id);
				WRITE_ONCE(td->len, seg_len);
				WRITE_ONCE(td->off, off);
				WRITE_ONCE(td->flags, 0);
			pr_warn("TRB emit store frag: buf_id=%u skb=%px users=%d active_ext=%u ext=%px trb_pkt=%u trb_head_ix=%u\n",
				buf_id, skb, refcount_read(&skb->users),
				skb->active_extensions, skb->extensions,
				skb->trb_pkt, skb->trb_head_page_ix);
			page_pool_ref_page(qctx->bufs[buf_id].page);
			qctx->bufs[buf_id].inflight++;
			(*seg_idx)++;
		}

		skb_walk_frags(skb, frag_skb) {
	        pr_warn("Walking SKB frags\n");
			int err = trb_emit_segments_pp_one(qctx, frag_skb, prod, seg_idx,
							    conn_id);
			if (err)
				return err;
		}

	return 0;
}

/* Local copy of tcp_eat_recv_skb (not exported) to consume a skb from the rx queue */
static void trb_tcp_eat_recv_skb(struct sock *sk, struct sk_buff *skb)
{
	__skb_unlink(skb, &sk->sk_receive_queue);
	if (likely(skb->destructor == sock_rfree)) {
		sock_rfree(skb);
		skb->destructor = NULL;
		skb->sk = NULL;
		skb_attempt_defer_free(skb);
		return;
	}
	__kfree_skb(skb);
}

/* Called after tcp_data_queue(); emit one descriptor per page-pool payload buffer. */
int trb_tcp_queue_skb(struct queue_ctx *qctx, struct sock *sk,
		      struct sk_buff *skb)
{
	struct descriptor_ring *dr;
	struct tcp_sock *tp;
	u32 prod;
	u32 con;
	u64 conn_id;
	int seg_count;
	int seg_idx;
	int desc_count;
	u32 total_bytes;
	bool close_desc;

	if (!qctx || !qctx->dr || !qctx->pp || !qctx->bufs || !skb)
		return -ENODEV;

	dr = qctx->dr;
	tp = tcp_sk(sk);
	conn_id = READ_ONCE(sk->sk_trb_conn_id);

	con = smp_load_acquire(&dr->con);
	prod = READ_ONCE(dr->prod);
	seg_count = trb_count_segments_pp(skb);
	close_desc = TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN;
	desc_count = seg_count + (close_desc ? 1 : 0);

	if (!desc_count)
		return -EOPNOTSUPP;
	if (prod - con + desc_count > dr->desc_cap)
		return -ENOSPC;

	seg_idx = 0;
	if (seg_count &&
	    trb_emit_segments_pp_one(qctx, skb, prod, &seg_idx, conn_id))
		return -EINVAL;
	if (close_desc) {
		trb_emit_close_desc(qctx, prod + seg_idx, conn_id);
		seg_idx++;
	}

	trb_tcp_eat_recv_skb(sk, skb);
	total_bytes = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq;
	WRITE_ONCE(tp->copied_seq, TCP_SKB_CB(skb)->end_seq);
	tcp_cleanup_rbuf(sk, total_bytes);
	tcp_rcv_space_adjust(sk);

	return trb_publish_and_signal(qctx, prod + seg_idx);
}
EXPORT_SYMBOL_GPL(trb_tcp_queue_skb);
static void __exit trb_exit(void)
{
	misc_deregister(&trb_misc);
}

module_init(trb_init);
module_exit(trb_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ayesha Naeem");
MODULE_DESCRIPTION("Minimal RX ring mmap device for zero-copy RX");
