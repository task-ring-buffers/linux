/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_TRB_H
#define _NET_TRB_H

#include <linux/errno.h>
#include <linux/types.h>
#include <net/page_pool/types.h>

struct queue_ctx;
struct sock;
struct sk_buff;

/* Both need struct queue_ctx *q arg which will be added later when we expand to multi queus */
#ifdef CONFIG_TRB_RX_RING_DEV
struct page_pool *trb_register_pp(struct page_pool_params *pp, size_t buf_size);
struct page *trb_page_pool_alloc(u32 *idx);
int trb_free_ring_return(struct page *page, u32 idx);
int trb_tcp_queue_skb( struct sock *sk,
		      struct sk_buff *skb);
#else
static inline struct page_pool *trb_register_pp(struct page_pool_params *pp, size_t buf_size)
{
	return ERR_PTR(-EOPNOTSUPP);
}
static inline struct page *trb_page_pool_alloc(u32 *idx)
{
	(void)idx;
	return NULL;
}
static inline int trb_free_ring_return(struct page *page, u32 idx)
{
	(void)page;
	(void)idx;
	return -EOPNOTSUPP;
}
static inline int trb_tcp_queue_skb(struct sock *sk,
				    struct sk_buff *skb)
{
	return -EOPNOTSUPP;
}
#endif

#endif /* _NET_TRB_H */
