#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/miscdevice.h>


#define PAGE_ORDER 0
#define RX_RING_SIZE 64
#define DEV_NAME "trb_dev"

static int rx_num_pages;
static struct page **rx_pages;

/*
struct trb_rx_buffer {
        struct page *page;
        dma_addr_t dma;
        bool in_use;
}       

struct trb_rx_dev {
        struct trb_rx_buffer bufs[RX_RING_SIZE];
        struct device *dma_device;
        struct cdev cdev; 
        dev_t dev_no;
        struct class *class;
}       

static struct trb_rx_dev *rx_dev;
*/

static int rx_ring_mmap(struct file *file, struct vm_area_struct *vma)
{
        unsigned long len = vma->vm_end - vma->vm_start;
        unsigned long start = vma->vm_start;
        int i;
        
	vm_flags_set(vma, VM_IO | VM_DONTEXPAND | VM_DONTDUMP);

        if (len > (rx_num_pages << PAGE_SHIFT))
                return -EINVAL;
        for (i = 0; i < rx_num_pages; i++) {
		if (remap_pfn_range(vma, start, page_to_pfn(rx_pages[i]), PAGE_SIZE, vma->vm_page_prot))
			return -EAGAIN;
		start += PAGE_SIZE;
        }
	return 0;
}

static const struct file_operations rx_ring_fops = {
        .owner = THIS_MODULE,
        .mmap = rx_ring_mmap,
};
static struct miscdevice rx_ring_miscdev = {
        .minor = MISC_DYNAMIC_MINOR,
        .name = "trb_dev",
        .fops = &rx_ring_fops,
	.mode = 0666,
};
static int __init rx_ring_init(void)
{
	int i;
	int err = 0;
	rx_num_pages = RX_RING_SIZE;
	rx_pages = kcalloc(rx_num_pages, sizeof(struct page *), GFP_KERNEL);
	if (!rx_pages)
		return -ENOMEM;
	for (i = 0; i < rx_num_pages ; i++) {
		rx_pages[i] = alloc_pages(GFP_KERNEL | __GFP_ZERO, PAGE_ORDER);
		if (!rx_pages[i]) {
			err = PTR_ERR(rx_pages[i]);
			goto err;
		}
	}

	goto out;
err:
	while (i >= 0){
		__free_pages(rx_pages[i], PAGE_ORDER);
		i--;
	}
	kfree(rx_pages);
	return err;
out:

	return misc_register(&rx_ring_miscdev);
}

static void __exit rx_ring_exit(void)
{
    int i;

    for (i = 0; i < rx_num_pages; i++)
	    __free_pages(rx_pages[i], PAGE_ORDER);

    kfree(rx_pages);
    misc_deregister(&rx_ring_miscdev);
}

module_init(rx_ring_init);
module_exit(rx_ring_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ayesha Naeem");
MODULE_DESCRIPTION("Minimal RX ring mmap device for zero-copy RX");
