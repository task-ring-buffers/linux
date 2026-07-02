#ifndef _TRB_IDS_H_
#define _TRB_IDS_H_

#include <linux/gfp_types.h>
#include <linux/types.h>

struct trb_ids_allocator;

struct trb_ids_allocator *trb_ids_create(u32 max_ids, gfp_t gfp);
void trb_ids_destroy(struct trb_ids_allocator *alloc);

int trb_id_alloc(struct trb_ids_allocator *alloc, u32 *id_out);
void trb_id_free(struct trb_ids_allocator *alloc, u32 id);

#endif /* _TRB_IDS_H_ */
