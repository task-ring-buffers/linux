#include <linux/bitmap.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include "trb_ids.h"

struct trb_ids_allocator {
	spinlock_t lock;
	u32 max_ids;
	unsigned long *bitmap;
};

struct trb_ids_allocator *trb_ids_create(u32 max_ids, gfp_t gfp)
{
	struct trb_ids_allocator *alloc;

	if (!max_ids)
		return NULL;

	alloc = kzalloc(sizeof(*alloc), gfp);
	if (!alloc)
		return NULL;

	alloc->bitmap = bitmap_zalloc(max_ids, gfp);
	if (!alloc->bitmap) {
		kfree(alloc);
		return NULL;
	}

	spin_lock_init(&alloc->lock);
	alloc->max_ids = max_ids;
	return alloc;
}

void trb_ids_destroy(struct trb_ids_allocator *alloc)
{
	if (!alloc)
		return;

	bitmap_free(alloc->bitmap);
	kfree(alloc);
}

int trb_id_alloc(struct trb_ids_allocator *alloc, u32 *id_out)
{
	unsigned long id;

	if (!alloc || !id_out)
		return -EINVAL;

	spin_lock(&alloc->lock);
	id = find_next_zero_bit(alloc->bitmap, alloc->max_ids, 1);
	if (id >= alloc->max_ids) {
		spin_unlock(&alloc->lock);
		return -ENOSPC;
	}

	__set_bit(id, alloc->bitmap);
	spin_unlock(&alloc->lock);

	*id_out = (u32)id;
	return 0;
}

void trb_id_free(struct trb_ids_allocator *alloc, u32 id)
{
	if (!alloc || !id || id >= alloc->max_ids)
		return;

	spin_lock(&alloc->lock);
	__clear_bit(id, alloc->bitmap);
	spin_unlock(&alloc->lock);
}
