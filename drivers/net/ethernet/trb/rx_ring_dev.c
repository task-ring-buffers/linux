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
    
    pr_warn("Len: %u Need %u\n", len, need);
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

static int build_meta_and_userspace_pool(struct trb_dev *d)
{
    size_t hdr_sz, desc_bytes, meta_bytes;
    struct rx_ring_hdr *hdr;
    struct recycle_ring * rr;
    struct trb_desc *rxds;
    struct page_pool_params pp;
    struct page *pg;
    void *base;
    int ret = 0;
    int i = 0;

    /* Layout (all inside meta_base):
     *   base + 0                     : struct rx_ring_hdr
     *   base + hdr_sz                : trb_desc[DESC_CAP]
     *   base + hdr_sz + desc_bytes   : struct ring_u32 + entries[FILL_CAP]
     *   base + hdr_sz + recycle_bytes: Empty reserved memory
     *   meta_bytes (3 PAGES)         : end of meta; payload starts at pool_off
     */

    hdr_sz = sizeof(struct rx_ring_hdr);
    desc_bytes = sizeof(struct trb_desc) * DESC_CAP;
    //recycle_bytes = sizeof(struct recycle_ring) + sizeof(__u32) * FILL_CAP;
    meta_bytes = META_PAGES * PAGE_SIZE;

    base = vzalloc(meta_bytes);
    if (!base)
        return -ENOMEM;

    d->meta_base = base;
    d->meta_bytes = meta_bytes;

    hdr = d->hdr = (struct rx_ring_hdr*) base;
    rxds = d->rx_desc = (struct trb_desc*) ((__u8*)base + hdr_sz);
    rr = d->rr = (struct recycle_ring*) ((__u8*)base + hdr_sz + desc_bytes);

    WRITE_ONCE(hdr->prod, 0);
    WRITE_ONCE(hdr->con, 0);
    WRITE_ONCE(hdr->doorbell, 0);
    hdr->desc_cap = DESC_CAP;
    hdr->buf_size = BUF_SIZE;
    hdr->fill_cap = FILL_CAP;
    hdr->desc_off = hdr_sz;

    rr->prod = rr->con = 0;
    rr->cap = FILL_CAP;
    rr->mask = FILL_CAP - 1;
    hdr->rr_off = hdr->desc_off + desc_bytes;

     /* Allocate payload pages from page_pool. In a real NIC path, set
     *   pp_params.dev = netdev->dev and pp_params.flags |= PP_FLAG_DMA_MAP
     * so pages come pre-mapped for DMA and page_pool tracks DMA addresses. */

    pp.order = 0;
    pp.flags = 0;
    pp.flags = 0;
    pp.pool_size = VM_TOTAL_PAGES;
    pp.nid = numa_node_id();
    pp.dev = NULL;
    pp.dma_dir = DMA_FROM_DEVICE;

    d->pp = page_pool_create(&pp);
    if (!d->pp) {
        ret = -ENOMEM;
        goto err_pp;
    }

    d->bufs = kcalloc(VM_TOTAL_PAGES, sizeof(*d->bufs), GFP_KERNEL);
    d->pages = kcalloc(VM_TOTAL_PAGES, sizeof(*d->pages), GFP_KERNEL);
    if (!d->bufs || !d->pages) {
        ret = -ENOMEM;
        goto err_buf_page;
    }

    for (i = 0; i < VM_TOTAL_PAGES ; i++) {
        pg = page_pool_dev_alloc_pages(d->pp);
        if (!pg) {
            ret = -ENOMEM;
            goto err_buf_page;
        }
        d->bufs[i].page = pg;
        d->bufs[i].dma_base = 0;
        d->pages[i] = pg;
    }

    hdr->buf_cap = VM_TOTAL_PAGES;
    hdr->pool_size = (__u64)VM_TOTAL_PAGES * BUF_SIZE;
    hdr->pool_off = ALIGN(meta_bytes, PAGE_SIZE);

    for (i = 0; i < d->hdr->buf_cap; i++)
        rr_push(d->rr, i);

    goto out;

err_buf_page:
    kfree(d->bufs);
    kfree(d->pages);
    page_pool_destroy(d->pp);

err_pp:
    vfree(base);

out:
    return ret;
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
    struct queue_ctx *q = kzalloc(sizeof(*q), GFP_KERNEL);;
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
    int i;
    rx_dev = kzalloc(sizeof(struct trb_dev), GFP_KERNEL);
    if (!rx_dev)
        return -ENOMEM;
    
    ret = build_meta_and_userspace_pool(rx_dev);
    if (ret) {
        kfree(rx_dev);
        return ret;
    }
    rx_dev->misc.minor = MISC_DYNAMIC_MINOR;
    rx_dev->misc.name = "trb_dev";
    rx_dev->misc.fops = &trb_fops;
    rx_dev->misc.mode = 0666;

    ret = misc_register(&rx_dev->misc);
    if (ret) {
        if (rx_dev->bufs) {
            for (i = 0; i < rx_dev->hdr->buf_cap; i++) {
                if (rx_dev->bufs[i].page)
                    page_pool_put_page(rx_dev->pp, rx_dev->bufs[i].page, 0, true);
            }
            kfree(rx_dev->bufs);
            kfree(rx_dev->pages);
            if (rx_dev->pp)
                page_pool_destroy(rx_dev->pp);
            vfree(rx_dev->meta_base);
            kfree(rx_dev);
            return ret;
        }
    }
    pr_info("%s: ready. buf_cap=%u desc_cap=%u", DEV_NAME, rx_dev->hdr->buf_cap, rx_dev->hdr->desc_cap);
    return 0;
}

static void __exit trb_exit(void)
{
    int i;
    if (rx_dev) {
        misc_deregister(&rx_dev->misc);
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
        kfree(rx_dev);
        }
}

module_init(trb_init);
module_exit(trb_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ayesha Naeem");
MODULE_DESCRIPTION("Minimal RX ring mmap device for zero-copy RX");
