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
#include <net/page_pool/types.h>
#include <net/page_pool/helpers.h>
#include <net/netmem.h>
#include <net/tcp.h>
#include <linux/poison.h>
#include <linux/highmem.h>

#define META_PAGES 3
#define VM_TOTAL_PAGES 256
#define DEV_NAME "trb_dev"

/* Ring capacity must be powers of two for mask-based indexing */
#define DESC_CAP 64     /* kernel -> user descriptors */
#define FILL_CAP 256     /* user -> kernel buf_id ring */  /* should the size equal desc size or num_buffers */

/* Switch to pp_frag for sub_page buffers */
#define BUF_SIZE PAGE_SIZE


#define IOCTL_REGISTER_EFD _IOW('m', 1, int)

#define IOCTL_TEST_PRODUCE _IOW('m', 2, u32)

struct rx_ring_hdr {
    /* RX descriptor ring indices (SPSC):
     *  - prod: written by KERNEL (store-release)
     *  - con: written by USER (store-release)
     *  Consumer read counterparts with load-acquire before dereferencing */
    __u32 prod;
    __u32 con;

    /* Total payload bytes mapped */
    __u64 pool_size;

    /* Byte offsets from the beginning of the mapping to each region */
    __u64 pool_off;     /* Payload starts here */
    __u64 desc_off;     /* Descriptors start here */
    __u64 rr_off;     /* fill ring hdr */

    __u32 buf_cap;
    __u32 desc_cap;
    __u32 fill_cap;
    __u32 buf_size;
    
    __u32 doorbell;
};

struct trb_desc {
    __u32 buf_id; /* index into payload buffers (0 ... buf_cap - 1) */
    __u32 len;    /* valid bytes starting at off */
    __u32 off;    /* byte offset within the buffer */
    __u32 flags;  /* future use */
};

struct recycle_ring {
    __u32 prod;
    __u32 con;
    __u32 cap;
    __u32 mask;
    __u32 entries[];
};

/* Kernel private state */

struct buf_map_entry {
	struct page *page;
	dma_addr_t dma_base;
	struct sk_buff *skb_ref; /* extra ref held while userspace reads */
};

struct trb_dev {
    
    struct miscdevice misc;

    /* Vmalloc-ed meta region holding, hdr, desc, and recycle ring */
    void *meta_base;
    size_t meta_bytes;
    struct rx_ring_hdr *hdr;
    struct trb_desc *rx_desc;
    struct recycle_ring *rr;

    /* Payload backing via page_pool */
    struct page_pool *pp;
    struct buf_map_entry *bufs;
    struct page **pages;

};

struct queue_ctx {
    struct trb_dev *dev;
    struct eventfd_ctx *efd;
};

struct trb_dev *rx_dev;
static bool trb_dev_ready;

struct queue_ctx *q;

/* Exported TRB helpers */
struct page_pool *trb_register_pp(struct page_pool_params *pp, size_t buf_size);
int trb_tcp_queue_skb(struct sock *sk, struct sk_buff *skb);
struct page *trb_page_pool_alloc(struct page_pool *pool);
static int build_meta_and_userspace_pool(struct trb_dev *d);

static int trb_prepare_dev(void)
{
	int ret;

	if (trb_dev_ready)
		return 0;

	rx_dev = kzalloc(sizeof(struct trb_dev), GFP_KERNEL);
	if (!rx_dev)
		return -ENOMEM;

	ret = build_meta_and_userspace_pool(rx_dev);
	if (ret) {
		kfree(rx_dev);
		rx_dev = NULL;
		return ret;
	}

	trb_dev_ready = true;
	return 0;
}

static int trb_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct queue_ctx *q = file->private_data;
	struct trb_dev *d = q->dev;
	unsigned long len = vma->vm_end - vma->vm_start;
    unsigned long need = d->hdr->pool_off + (unsigned long)d->hdr->buf_cap * BUF_SIZE;
    unsigned long pool_pages = DIV_ROUND_UP((unsigned long)d->hdr->pool_size, PAGE_SIZE);
    unsigned long uaddr;
    struct page *pg;
    int i, ret;
    int off = 0;
    
    pr_warn("Len: %lu Need %lu\n", len, need);
    if (len < need)
        return -EINVAL;
    for (off = 0; off < d->meta_bytes ; off += PAGE_SIZE) {
        pg = vmalloc_to_page((__u8*)d->meta_base + off);
        if (!pg)
            return -EFAULT;
        ret = vm_insert_page(vma, vma->vm_start + off, pg);
        if (ret)
            return ret;
    }

    uaddr = vma->vm_start + d->hdr->pool_off;
    for (i = 0; i < pool_pages; i++, uaddr += PAGE_SIZE) {
        ret = vm_insert_page(vma, uaddr, d->pages[i]);
        if (ret)
            return ret;
    }

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

/* Placeholder: assume userspace provides buf_ids to recycle */
static void drain_rr(struct recycle_ring *rr)
{
	struct trb_dev *dev = rx_dev;
	__u32 buf_id;

	if (!dev || !rr)
		return;

	while (rr_pop(rr, &buf_id)) {
		if (buf_id >= dev->hdr->buf_cap)
			continue;
		if (dev->bufs[buf_id].skb_ref) {
			kfree_skb(dev->bufs[buf_id].skb_ref);
			dev->bufs[buf_id].skb_ref = NULL;
		}
	}
}
/* This should also obviously take a queue context when hooked up with multiple cores */
struct page_pool *trb_register_pp(struct page_pool_params *pp, size_t buf_size)
{
	struct trb_dev *dev;
	struct rx_ring_hdr *hdr;
	struct page_pool *pool;
	struct page *pg;
	size_t bufs_per_page;
	size_t total_bufs;
	size_t i, j, idx;
	unsigned long page_bytes;
	int err = -EINVAL;

	if (!pp || !buf_size)
		return ERR_PTR(-EINVAL);

	if (!trb_dev_ready) {
		int ret = trb_prepare_dev();
		if (ret)
			return ERR_PTR(ret);
	}

	dev = rx_dev;
	hdr = dev->hdr;

	pool = page_pool_create(pp);
	if (IS_ERR(pool))
		return pool;

	page_bytes = PAGE_SIZE << pp->order;
	bufs_per_page = DIV_ROUND_UP(page_bytes, buf_size);
	total_bufs = (size_t)pp->pool_size * bufs_per_page;

	dev->pp = pool;

	dev->pages = kcalloc(pp->pool_size, sizeof(*dev->pages), GFP_KERNEL);
	if (!dev->pages) {
		err = -ENOMEM;
		goto err_destroy_pool;
	}

	dev->bufs = kcalloc(total_bufs, sizeof(*dev->bufs), GFP_KERNEL);
	if (!dev->bufs) {
		err = -ENOMEM;
		goto err_free_pages;
	}

	for (i = 0; i < pp->pool_size; i++) {
		pg = page_pool_dev_alloc_pages(pool);
		if (!pg) {
			err = -ENOMEM;
			goto err_release_pages;
		}

		dev->pages[i] = pg;
		WRITE_ONCE(pg->_pp_mapping_pad, (unsigned long)i);

		for (j = 0; j < bufs_per_page; j++) {
			idx = i * bufs_per_page + j;
			dev->bufs[idx].page = pg;
			dev->bufs[idx].dma_base = (dma_addr_t)(j * buf_size);
		}
	}

	for (i = 0; i < pp->pool_size; i++) {
		if (dev->pages[i])
			page_pool_put_page(pool, dev->pages[i], 0, true);
	}

	hdr->buf_size = buf_size;
	hdr->buf_cap = total_bufs;
	hdr->pool_size = (__u64)total_bufs * buf_size;

	return pool;

err_release_pages:
	while (i--) {
		if (dev->pages[i]) {
			page_pool_put_page(pool, dev->pages[i], 0, true);
			dev->pages[i] = NULL;
		}
	}
	kfree(dev->bufs);
	dev->bufs = NULL;
err_free_pages:
	kfree(dev->pages);
	dev->pages = NULL;
err_destroy_pool:
	page_pool_destroy(pool);
	dev->pp = NULL;
	return ERR_PTR(err);
}

static int build_meta_and_userspace_pool(struct trb_dev *d)
{
	size_t hdr_sz, desc_bytes, recycle_bytes, need_bytes, meta_bytes;
	struct rx_ring_hdr *hdr;
	struct recycle_ring *rr;
	struct trb_desc *rxds;
	void *base;

	/* Layout (all inside meta_base):
	 *   base + 0                     : struct rx_ring_hdr
	 *   base + hdr_sz                : trb_desc[DESC_CAP]
	 *   base + hdr_sz + desc_bytes   : struct recycle_ring + entries[FILL_CAP]
	 *   meta_bytes (>= 3 PAGES)      : end of meta; payload starts at pool_off
	 */

	hdr_sz = sizeof(struct rx_ring_hdr);
	desc_bytes = sizeof(struct trb_desc) * DESC_CAP;
	recycle_bytes = sizeof(struct recycle_ring) + sizeof(__u32) * FILL_CAP;

	need_bytes = ALIGN(hdr_sz + desc_bytes + recycle_bytes, PAGE_SIZE);
	meta_bytes = META_PAGES * PAGE_SIZE;
	if (meta_bytes < need_bytes)
		meta_bytes = need_bytes;

	base = vzalloc(meta_bytes);
	if (!base)
		return -ENOMEM;

	d->meta_base = base;
	d->meta_bytes = meta_bytes;

	hdr = d->hdr = (struct rx_ring_hdr *)base;
	rxds = d->rx_desc = (struct trb_desc *)((__u8 *)base + hdr_sz);
	rr = d->rr = (struct recycle_ring *)((__u8 *)base + hdr_sz + desc_bytes);

	WRITE_ONCE(hdr->prod, 0);
	WRITE_ONCE(hdr->con, 0);
	WRITE_ONCE(hdr->doorbell, 0);
	hdr->desc_cap = DESC_CAP;
	hdr->fill_cap = FILL_CAP;
	hdr->desc_off = hdr_sz;

	rr->prod = rr->con = 0;
	rr->cap = FILL_CAP;
	rr->mask = FILL_CAP - 1;
	hdr->rr_off = hdr->desc_off + desc_bytes;
	hdr->pool_off = ALIGN(meta_bytes, PAGE_SIZE);

	return 0;
}

/* test and publish functions here */

static int trb_publish_and_signal(struct queue_ctx *q, u32 new_prod)
{
    struct rx_ring_hdr *hdr = q->dev->hdr;
    bool was_empty = READ_ONCE(hdr->prod) == READ_ONCE(hdr->con);

    smp_store_release(&hdr->prod, new_prod);

    if (was_empty && likely(q->efd)) {
        WRITE_ONCE(hdr->doorbell, READ_ONCE(hdr->doorbell) + 1);
        eventfd_signal(q->efd);
    }
    return 0;
}

static void test_buffers(struct queue_ctx *q, __u32 n)
{
    struct trb_dev *dev = q->dev;
    struct rx_ring_hdr *hdr = q->dev->hdr;
    __u32 prod = READ_ONCE(hdr->prod);
    int made = 0;
    __u32 buf_id;
    struct page *pg;
    struct trb_desc *td;
    void *kva;
    int len;
    int j;

    while (made < n ) {
        if (!rr_pop(dev->rr, &buf_id))
            break;
        if (buf_id >= hdr->buf_cap)
            break;
        pg = dev->bufs[buf_id].page;
        kva = kmap_local_page(pg);
        len = min_t(int, 128 + prod * 8, hdr->buf_size);
        for (j = 0; j < len; j++)
            ((__u8*)kva)[j] = 0xA0 + ((prod + j) & 0x1F);
        kunmap_local(kva);

        td = &dev->rx_desc[prod & (hdr->desc_cap - 1)];
        WRITE_ONCE(td->buf_id, buf_id);
        WRITE_ONCE(td->len, len);
        WRITE_ONCE(td->off, 0);
        WRITE_ONCE(td->flags, 0);
        prod++;
        made++;

    }

    /* TO DO */


}

static long trb_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct queue_ctx *q = file->private_data;
    struct rx_ring_hdr *hdr = q->dev->hdr;
    struct eventfd_ctx *efd;

    switch (cmd) {
    case IOCTL_REGISTER_EFD: {
        int efd_fd;
        if (copy_from_user(&efd_fd, (void __user*) arg, sizeof(efd_fd)))
            return -EFAULT;
        if (q->efd) {
            eventfd_ctx_put(q->efd);
            q->efd = NULL;
        }
        efd = eventfd_ctx_fdget(efd_fd);
        if (IS_ERR(efd)) return PTR_ERR(efd);
        q->efd = efd;
        return 0;
                 }
    case IOCTL_TEST_PRODUCE: {
        u32 add;
        u32 cur;
        if (copy_from_user(&add, (void __user*) arg, sizeof(add)))
            return -EFAULT;
        cur = READ_ONCE(hdr->prod);
        test_buffers(q, add);
        return trb_publish_and_signal(q, cur + add);
                 }
    default:
        return -ENOIOCTLCMD;
    }
}



static int trb_open(struct inode *ino, struct file *file)
{
    q = kzalloc(sizeof(*q), GFP_KERNEL);
   // struct queue_ctx *q = kzalloc(sizeof(*q), GFP_KERNEL);;
    if (!q) 
        return -ENOMEM;
    q->dev = rx_dev;
    q->efd = NULL;
    file->private_data = q;
    return 0;
}

static int trb_release(struct inode *ino, struct file *file)
{
    struct queue_ctx *q = file->private_data;
    if (q) {
        if (q->efd)
            eventfd_ctx_put(q->efd);
        kfree(q);
    }
    return 0;
}

static const struct file_operations trb_fops = {
    .owner = THIS_MODULE,
    .mmap = trb_mmap,
    .open = trb_open,
    .release = trb_release,
    .unlocked_ioctl = trb_ioctl,
};
static int __init trb_init(void)
{
    int ret;

    rx_dev = NULL;
    trb_dev_ready = false;

    /*
     * Only register the miscdevice at init; actual ring/pool
     * allocation is deferred to the first trb_register_pp() call
     * when a TRB-enabled RQ is created.
     */
    rx_dev = kzalloc(sizeof(struct trb_dev), GFP_KERNEL);
    if (!rx_dev)
        return -ENOMEM;

    rx_dev->misc.minor = MISC_DYNAMIC_MINOR;
    rx_dev->misc.name = "trb_dev";
    rx_dev->misc.fops = &trb_fops;
    rx_dev->misc.mode = 0666;

    ret = misc_register(&rx_dev->misc);
    if (ret) {
        kfree(rx_dev);
        rx_dev = NULL;
        return ret;
    }
    pr_info("%s: registered (deferred init)", DEV_NAME);
	return 0;
}

#ifdef CONFIG_PAGE_POOL_STATS
#define trb_alloc_stat_inc(pool, field) ((pool)->alloc_stats.field++)
#else
#define trb_alloc_stat_inc(pool, field) do { } while (0)
#endif

static netmem_ref trb_page_pool_refill_cache(struct page_pool *pool)
{
	struct ptr_ring *ring = &pool->ring;
	netmem_ref netmem;

	if (__ptr_ring_empty(ring)) {
		trb_alloc_stat_inc(pool, empty);
		return 0;
	}

	do {
		netmem = (__force netmem_ref)__ptr_ring_consume(ring);
		if (!netmem)
			break;

		pool->alloc.cache[pool->alloc.count++] = netmem;
	} while (pool->alloc.count < PP_ALLOC_CACHE_REFILL);

	if (!pool->alloc.count)
		return 0;

	trb_alloc_stat_inc(pool, refill);
	return pool->alloc.cache[--pool->alloc.count];
}

static struct page *trb_page_pool_dev_alloc_fast(struct page_pool *pool)
{
	netmem_ref netmem;

	if (likely(pool->alloc.count)) {
		netmem = pool->alloc.cache[--pool->alloc.count];
		trb_alloc_stat_inc(pool, fast);
		return netmem_to_page(netmem);
	}

	netmem = trb_page_pool_refill_cache(pool);
	if (!netmem)
		return NULL;

	return netmem_to_page(netmem);
}

/* signature should take argument page_pool and queue_ctx. queue_ctx should help obtain the rr pointer when there is more than one core */
struct page* trb_page_pool_alloc(struct page_pool* pool)
{
	struct trb_dev *dev = rx_dev;

	if (!dev)
		return NULL;

	if (dev->rr)
		drain_rr(dev->rr);

	return trb_page_pool_dev_alloc_fast(pool);
}
EXPORT_SYMBOL_GPL(trb_page_pool_alloc);

static inline bool trb_is_pp_page(struct page *page)
{
	return (page->pp_magic & ~0x3UL) == PP_SIGNATURE;
}

static int trb_buf_from_region(struct trb_dev *dev, struct page *page,
			       u32 payload_start, u32 len,
			       u32 *buf_id, u32 *off, u32 *seg_len)
{
	u32 page_ix;
	u32 bufs_per_page;
	u32 page_bytes;
	u32 buf_idx_in_page;

	if (!page || !len)
		return -EINVAL;

	page_ix = READ_ONCE(page->_pp_mapping_pad);
	page_bytes = PAGE_SIZE << compound_order(page);
	bufs_per_page = DIV_ROUND_UP(page_bytes, dev->hdr->buf_size);

	if (page_ix >= dev->hdr->buf_cap)
		return -EINVAL;
	if (payload_start >= page_bytes)
		return -EINVAL;

	buf_idx_in_page = payload_start / dev->hdr->buf_size;
	*buf_id = page_ix * bufs_per_page + buf_idx_in_page;
	*off = payload_start % dev->hdr->buf_size;
	*seg_len = min_t(u32, len, dev->hdr->buf_size - *off);
	return 0;
}

static int trb_count_segments_pp(struct sk_buff *skb)
{
	struct sk_buff *iter;
	int count;

	iter = skb;
	count = 0;
	for (; iter; iter = iter->next) {
		struct skb_shared_info *sh;
		struct page *head_page;
		u32 head_len;
		int i;

		sh = skb_shinfo(iter);
		head_page = virt_to_head_page(iter->data);
		head_len = skb_headlen(iter);

		if (head_len && trb_is_pp_page(head_page))
			count++;
		for (i = 0; i < sh->nr_frags; i++) {
			if (trb_is_pp_page(skb_frag_page(&sh->frags[i])))
				count++;
		}
		if (sh->frag_list) {
			iter = sh->frag_list;
			continue;
		}
	}
	return count;
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

/* Called after tcp_data_queue(); emit one descriptor per page-pool payload buffer. It should also have a struct queue_ctx *q param but for  not there is only 1 ctx and i have made it global */
int trb_tcp_queue_skb( struct sock *sk, struct sk_buff *skb)
{
	struct trb_dev *dev;
	struct rx_ring_hdr *hdr;
	struct trb_desc *td;
	struct tcp_sock *tp;
	struct sk_buff *iter;
	struct queue_ctx *ctx = q;
	u32 prod;
	u32 con;
	int seg_count;
	int seg_idx;
	u32 total_bytes;

	dev = ctx ? ctx->dev : NULL;
	if (!dev || !dev->hdr || !dev->pp || !skb)
		return -ENODEV;

	hdr = dev->hdr;
	tp = tcp_sk(sk);

	con = smp_load_acquire(&hdr->con);
	prod = READ_ONCE(hdr->prod);
	seg_count = trb_count_segments_pp(skb);
	if (!seg_count)
		return -EOPNOTSUPP;
	if (prod - con + seg_count > hdr->desc_cap)
		return -ENOSPC;

	seg_idx = 0;
	iter = skb;
	for (; iter; iter = iter->next) {
		struct skb_shared_info *sh;
		struct page *head_page;
		u32 head_len;
		int i;

		sh = skb_shinfo(iter);
		head_page = virt_to_head_page(iter->data);
		head_len = skb_headlen(iter);

		if (head_len && trb_is_pp_page(head_page)) {
			u32 buf_id;
			u32 off;
			u32 seg_len;
			u32 payload_start;

			payload_start = (u32)((unsigned long)iter->data -
					      (unsigned long)page_address(head_page));
			if (trb_buf_from_region(dev, head_page, payload_start,
						head_len, &buf_id, &off, &seg_len))
				return -EINVAL;

			td = &dev->rx_desc[(prod + seg_idx) & (hdr->desc_cap - 1)];
			WRITE_ONCE(td->buf_id, buf_id);
			WRITE_ONCE(td->len, seg_len);
			WRITE_ONCE(td->off, off);
			WRITE_ONCE(td->flags, 0);
			dev->bufs[buf_id].skb_ref = skb_get(iter);
			seg_idx++;
		}

		for (i = 0; i < sh->nr_frags; i++) {
			struct page *fp;
			u32 buf_id;
			u32 off;
			u32 seg_len;
			u32 payload_start;

			fp = skb_frag_page(&sh->frags[i]);
			if (!trb_is_pp_page(fp))
				continue;
			payload_start = skb_frag_off(&sh->frags[i]);
			if (trb_buf_from_region(dev, fp, payload_start,
						skb_frag_size(&sh->frags[i]),
						&buf_id, &off, &seg_len))
				return -EINVAL;

			td = &dev->rx_desc[(prod + seg_idx) & (hdr->desc_cap - 1)];
			WRITE_ONCE(td->buf_id, buf_id);
			WRITE_ONCE(td->len, seg_len);
			WRITE_ONCE(td->off, off);
			WRITE_ONCE(td->flags, 0);
			dev->bufs[buf_id].skb_ref = skb_get(iter);
			seg_idx++;
		}

		if (sh->frag_list) {
			iter = sh->frag_list;
			continue;
		}
	}

	trb_tcp_eat_recv_skb(sk, skb);
	total_bytes = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq;
	WRITE_ONCE(tp->copied_seq, TCP_SKB_CB(skb)->end_seq);
	tcp_cleanup_rbuf(sk, total_bytes);
	tcp_rcv_space_adjust(sk);

	return trb_publish_and_signal(ctx, prod + seg_idx);
}
EXPORT_SYMBOL_GPL(trb_tcp_queue_skb);
static void __exit trb_exit(void)
{
    int i;
    if (rx_dev) {
        misc_deregister(&rx_dev->misc);
        if (trb_dev_ready) {
            if (rx_dev->bufs) {
                for (i = 0; i < rx_dev->hdr->buf_cap; i++) {
                    if (rx_dev->bufs[i].page)
                        page_pool_put_page(rx_dev->pp, rx_dev->bufs[i].page, 0, true);
                }
            }
            kfree(rx_dev->bufs);
            kfree(rx_dev->pages);
            if (rx_dev->pp)
                page_pool_destroy(rx_dev->pp);
            vfree(rx_dev->meta_base);
        }
        kfree(rx_dev);
        }
}

module_init(trb_init);
module_exit(trb_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ayesha Naeem");
MODULE_DESCRIPTION("Minimal RX ring mmap device for zero-copy RX");
