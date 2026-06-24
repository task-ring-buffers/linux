/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_TRB_H
#define _NET_TRB_H

#include <linux/errno.h>
#include <linux/types.h>
#include <net/page_pool/types.h>

struct queue_ctx;
struct trb_dev;
struct sock;
struct sk_buff;

/* Both need struct queue_ctx *q arg which will be added later when we expand to multi queus */
#ifdef CONFIG_TRB_RX_RING_DEV
struct page_pool *trb_register_pp(struct page_pool_params *pp, size_t buf_size,
				  u16 rq_ix, struct trb_dev *dev,
				  struct queue_ctx **out_qctx);
struct page *trb_page_pool_alloc(struct queue_ctx *qctx, u32 *idx);
int trb_free_ring_return_ctx(struct queue_ctx *qctx, struct page *page, u32 idx);
int trb_tcp_queue_skb(struct queue_ctx *qctx, struct sock *sk,
		      struct sk_buff *skb);
void trb_accept_ready(struct sock *sk);
void trb_unregister_qctx(struct queue_ctx *qctx);
#else
static inline struct page_pool *trb_register_pp(struct page_pool_params *pp,
						size_t buf_size, u16 rq_ix,
						struct trb_dev *dev,
						struct queue_ctx **out_qctx)
{
	(void)rq_ix;
	(void)dev;
	if (out_qctx)
		*out_qctx = NULL;
	return ERR_PTR(-EOPNOTSUPP);
}
static inline struct page *trb_page_pool_alloc(struct queue_ctx *qctx, u32 *idx)
{
	(void)qctx;
	(void)idx;
	return NULL;
}
static inline int trb_free_ring_return_ctx(struct queue_ctx *qctx, struct page *page, u32 idx)
{
	(void)qctx;
	(void)page;
	(void)idx;
	return -EOPNOTSUPP;
}
static inline int trb_tcp_queue_skb(struct queue_ctx *qctx, struct sock *sk,
				    struct sk_buff *skb)
{
	(void)qctx;
	return -EOPNOTSUPP;
}
static inline void trb_accept_ready(struct sock *sk)
{
	(void)sk;
}
static inline void trb_unregister_qctx(struct queue_ctx *qctx)
{
	(void)qctx;
}
#endif

#endif /* _NET_TRB_H */
