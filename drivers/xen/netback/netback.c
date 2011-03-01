/******************************************************************************
 * drivers/xen/netback/netback.c
 *
 * Back-end of the driver for virtual network devices. This portion of the
 * driver exports a 'unified' network-device interface that can be accessed
 * by any operating system that implements a compatible front end. A
 * reference front-end implementation can be found in:
 *  drivers/xen/netfront/netfront.c
 *
 * Copyright (c) 2002-2005, K A Fraser
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "common.h"

#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/kthread.h>

#include <xen/balloon.h>
#include <xen/events.h>
#include <xen/interface/memory.h>

#include <asm/xen/hypercall.h>
#include <asm/xen/page.h>

/*define NETBE_DEBUG_INTERRUPT*/

struct xen_netbk *xen_netbk;
int xen_netbk_group_nr;

static void netif_idx_release(struct xen_netbk *netbk, u16 pending_idx);
static void make_tx_response(struct xen_netif *netif,
			     struct xen_netif_tx_request *txp,
			     s8       st);
static struct xen_netif_rx_response *make_rx_response(struct xen_netif *netif,
					     u16      id,
					     s8       st,
					     u16      offset,
					     u16      size,
					     u16      flags);

static void net_tx_action(unsigned long data);

static void net_rx_action(unsigned long data);

static inline unsigned long idx_to_pfn(struct xen_netbk *netbk,
				       unsigned int idx)
{
	return page_to_pfn(netbk->mmap_pages[idx]);
}

static inline unsigned long idx_to_kaddr(struct xen_netbk *netbk,
					 unsigned int idx)
{
	return (unsigned long)pfn_to_kaddr(idx_to_pfn(netbk, idx));
}

/* extra field used in struct page */
static inline void netif_set_page_ext(struct page *pg, unsigned int group,
		unsigned int idx)
{
	union page_ext ext = { .e = { .group = group + 1, .idx = idx } };

	BUILD_BUG_ON(sizeof(ext) > sizeof(ext.mapping));
	pg->mapping = ext.mapping;
}

static inline int netif_get_page_ext(struct page *pg, unsigned int *_group, unsigned int *_idx)
{
	union page_ext ext = { .mapping = pg->mapping };
	struct xen_netbk *netbk;
	unsigned int group, idx;

	if (!PageForeign(pg))
		return 0;

	group = ext.e.group - 1;

	if (group < 0 || group >= xen_netbk_group_nr)
		return 0;

	netbk = &xen_netbk[group];

	if (netbk->mmap_pages == NULL)
		return 0;

	idx = ext.e.idx;

	if ((idx < 0) || (idx >= MAX_PENDING_REQS))
		return 0;

	if (netbk->mmap_pages[idx] != pg)
		return 0;

	*_group = group;
	*_idx = idx;

	return 1;
}

/*
 * This is the amount of packet we copy rather than map, so that the
 * guest can't fiddle with the contents of the headers while we do
 * packet processing on them (netfilter, routing, etc). 72 is enough
 * to cover TCP+IP headers including options.
 */
#define PKT_PROT_LEN 72

static inline pending_ring_idx_t pending_index(unsigned i)
{
	return i & (MAX_PENDING_REQS-1);
}

static inline pending_ring_idx_t nr_pending_reqs(struct xen_netbk *netbk)
{
	return MAX_PENDING_REQS -
		netbk->pending_prod + netbk->pending_cons;
}

/* Setting this allows the safe use of this driver without netloop. */
static int MODPARM_copy_skb = 1;
module_param_named(copy_skb, MODPARM_copy_skb, bool, 0);
MODULE_PARM_DESC(copy_skb, "Copy data received from netfront without netloop");

int netbk_copy_skb_mode;

static int MODPARM_netback_kthread;
module_param_named(netback_kthread, MODPARM_netback_kthread, bool, 0);
MODULE_PARM_DESC(netback_kthread, "Use kernel thread to replace tasklet");

/*
 * Netback bottom half handler.
 * dir indicates the data direction.
 * rx: 1, tx: 0.
 */
static inline void xen_netbk_bh_handler(struct xen_netbk *netbk, int dir)
{
	if (MODPARM_netback_kthread)
		wake_up(&netbk->kthread.netbk_action_wq);
	else if (dir)
		tasklet_schedule(&netbk->tasklet.net_rx_tasklet);
	else
		tasklet_schedule(&netbk->tasklet.net_tx_tasklet);
}

static inline void maybe_schedule_tx_action(struct xen_netbk *netbk)
{
	smp_mb();
	if ((nr_pending_reqs(netbk) < (MAX_PENDING_REQS/2)) &&
	    !list_empty(&netbk->net_schedule_list))
		xen_netbk_bh_handler(netbk, 0);
}

static struct sk_buff *netbk_copy_skb(struct sk_buff *skb)
{
	struct skb_shared_info *ninfo;
	struct sk_buff *nskb;
	unsigned long offset;
	int ret;
	int len;
	int headlen;

	BUG_ON(skb_shinfo(skb)->frag_list != NULL);

	nskb = alloc_skb(SKB_MAX_HEAD(0), GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nskb))
		goto err;

	skb_reserve(nskb, NET_SKB_PAD + NET_IP_ALIGN);
	headlen = skb_end_pointer(nskb) - nskb->data;
	if (headlen > skb_headlen(skb))
		headlen = skb_headlen(skb);
	ret = skb_copy_bits(skb, 0, __skb_put(nskb, headlen), headlen);
	BUG_ON(ret);

	ninfo = skb_shinfo(nskb);
	ninfo->gso_size = skb_shinfo(skb)->gso_size;
	ninfo->gso_type = skb_shinfo(skb)->gso_type;

	offset = headlen;
	len = skb->len - headlen;

	nskb->len = skb->len;
	nskb->data_len = len;
	nskb->truesize += len;

	while (len) {
		struct page *page;
		int copy;
		int zero;

		if (unlikely(ninfo->nr_frags >= MAX_SKB_FRAGS)) {
			dump_stack();
			goto err_free;
		}

		copy = len >= PAGE_SIZE ? PAGE_SIZE : len;
		zero = len >= PAGE_SIZE ? 0 : __GFP_ZERO;

		page = alloc_page(GFP_ATOMIC | __GFP_NOWARN | zero);
		if (unlikely(!page))
			goto err_free;

		ret = skb_copy_bits(skb, offset, page_address(page), copy);
		BUG_ON(ret);

		ninfo->frags[ninfo->nr_frags].page = page;
		ninfo->frags[ninfo->nr_frags].page_offset = 0;
		ninfo->frags[ninfo->nr_frags].size = copy;
		ninfo->nr_frags++;

		offset += copy;
		len -= copy;
	}

#ifdef NET_SKBUFF_DATA_USES_OFFSET
	offset = 0;
#else
	offset = nskb->data - skb->data;
#endif

	nskb->transport_header = skb->transport_header + offset;
	nskb->network_header = skb->network_header + offset;
	nskb->mac_header = skb->mac_header + offset;

	return nskb;

 err_free:
	kfree_skb(nskb);
 err:
	return NULL;
}

static inline int netbk_max_required_rx_slots(struct xen_netif *netif)
{
	if (netif->can_sg || netif->gso || netif->gso_prefix)
		return MAX_SKB_FRAGS + 2; /* header + extra_info + frags */
	return 1; /* all in one */
}

static inline int netbk_queue_full(struct xen_netif *netif)
{
	RING_IDX peek   = netif->rx_req_cons_peek;
	RING_IDX needed = netbk_max_required_rx_slots(netif);

	return ((netif->rx.sring->req_prod - peek) < needed) ||
	       ((netif->rx.rsp_prod_pvt + NET_RX_RING_SIZE - peek) < needed);
}

static void tx_queue_callback(unsigned long data)
{
	struct xen_netif *netif = (struct xen_netif *)data;
	if (netif_schedulable(netif))
		netif_wake_queue(netif->dev);
}

/* Figure out how many ring slots we're going to need to send @skb to
   the guest. */
static unsigned count_skb_slots(struct sk_buff *skb, struct xen_netif *netif)
{
	unsigned count;
	unsigned copy_off;
	unsigned i;

	copy_off = 0;
	count = 1;

	BUG_ON(offset_in_page(skb->data) + skb_headlen(skb) > MAX_BUFFER_OFFSET);

	copy_off = skb_headlen(skb);

	if (skb_shinfo(skb)->gso_size)
		count++;

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		unsigned long size = skb_shinfo(skb)->frags[i].size;
		unsigned long bytes;
		while (size > 0) {
			BUG_ON(copy_off > MAX_BUFFER_OFFSET);

			/* These checks are the same as in netbk_gop_frag_copy */
			if (copy_off == MAX_BUFFER_OFFSET
			    || ((copy_off + size > MAX_BUFFER_OFFSET) && (size <= MAX_BUFFER_OFFSET) && copy_off)) {
				count++;
				copy_off = 0;
			}

			bytes = size;
			if (copy_off + bytes > MAX_BUFFER_OFFSET)
				bytes = MAX_BUFFER_OFFSET - copy_off;

			copy_off += bytes;
			size -= bytes;
		}
	}
	return count;
}

int netif_be_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct xen_netif *netif = netdev_priv(dev);
	struct xen_netbk *netbk;

	BUG_ON(skb->dev != dev);

	if (netif->group == -1)
		goto drop;

	netbk = &xen_netbk[netif->group];

	/* Drop the packet if the target domain has no receive buffers. */
	if (unlikely(!netif_schedulable(netif) || netbk_queue_full(netif)))
		goto drop;

	/*
	 * XXX For now we also copy skbuffs whose head crosses a page
	 * boundary, because netbk_gop_skb can't handle them.
	 */
	if ((skb_headlen(skb) + offset_in_page(skb->data)) >= PAGE_SIZE) {
		struct sk_buff *nskb = netbk_copy_skb(skb);
		if ( unlikely(nskb == NULL) )
			goto drop;
		/* Copy only the header fields we use in this driver. */
		nskb->dev = skb->dev;
		nskb->ip_summed = skb->ip_summed;
		dev_kfree_skb(skb);
		skb = nskb;
	}

	/* Reserve ring slots for the worst-case number of
	 * fragments. */
	netif->rx_req_cons_peek += count_skb_slots(skb, netif);
	netif_get(netif);

	if (netbk_can_queue(dev) && netbk_queue_full(netif)) {
		netif->rx.sring->req_event = netif->rx_req_cons_peek +
			netbk_max_required_rx_slots(netif);
		mb(); /* request notification /then/ check & stop the queue */
		if (netbk_queue_full(netif)) {
			netif_stop_queue(dev);
			/*
			 * Schedule 500ms timeout to restart the queue, thus
			 * ensuring that an inactive queue will be drained.
			 * Packets will be immediately be dropped until more
			 * receive buffers become available (see
			 * netbk_queue_full() check above).
			 */
			netif->tx_queue_timeout.data = (unsigned long)netif;
			netif->tx_queue_timeout.function = tx_queue_callback;
			mod_timer(&netif->tx_queue_timeout, jiffies + HZ/2);
		}
	}
	skb_queue_tail(&netbk->rx_queue, skb);

	xen_netbk_bh_handler(netbk, 1);

	return 0;

 drop:
	netif->stats.tx_dropped++;
	dev_kfree_skb(skb);
	return 0;
}

struct netrx_pending_operations {
	unsigned copy_prod, copy_cons;
	unsigned meta_prod, meta_cons;
	struct gnttab_copy *copy;
	struct netbk_rx_meta *meta;
	int copy_off;
	grant_ref_t copy_gref;
};

/* Set up the grant operations for this fragment.  If it's a flipping
   interface, we also set up the unmap request from here. */

static void netbk_gop_frag_copy(struct xen_netif *netif,
				struct netrx_pending_operations *npo,
				struct page *page, unsigned long size,
				unsigned long offset, int head)
{
	struct gnttab_copy *copy_gop;
	struct netbk_rx_meta *meta;
	/*
	 * These variables a used iff netif_get_page_ext returns true,
	 * in which case they are guaranteed to be initialized.
         */
	unsigned int uninitialized_var(group), uninitialized_var(idx);
	int foreign = netif_get_page_ext(page, &group, &idx);
	unsigned long bytes;

	/* Data must not cross a page boundary. */
	BUG_ON(size + offset > PAGE_SIZE);

	meta = npo->meta + npo->meta_prod - 1;

	while (size > 0) {
		BUG_ON(npo->copy_off > MAX_BUFFER_OFFSET);

		/*
		 * Move to a new receive buffer if:
		 *
		 * simple case: we have completely filled the current buffer.
		 *
		 * complex case: the current frag would overflow
		 * the current buffer but only if:
		 *     (i)   this frag would fit completely in the next buffer
		 * and (ii)  there is already some data in the current buffer
		 * and (iii) this is not the head buffer.
		 *
		 * Where:
		 * - (i) stops us splitting a frag into two copies
		 *   unless the frag is too large for a single buffer.
		 * - (ii) stops us from leaving a buffer pointlessly empty.
		 * - (iii) stops us leaving the first buffer
		 *   empty. Strictly speaking this is already covered
		 *   by (ii) but is explicitly checked because
		 *   netfront relies on the first buffer being
		 *   non-empty and can crash otherwise.
		 *
		 * This means we will effectively linearise small
		 * frags but do not needlessly split large buffers
		 * into multiple copies tend to give large frags their
		 * own buffers as before.
		 */
		if (npo->copy_off == MAX_BUFFER_OFFSET
		    || ((npo->copy_off + size > MAX_BUFFER_OFFSET) && (size <= MAX_BUFFER_OFFSET) && npo->copy_off && !head)) {
			struct xen_netif_rx_request *req;

			BUG_ON(head); /* Netfront requires there to be some data in the head buffer. */
			/* Overflowed this request, go to the next one */
			req = RING_GET_REQUEST(&netif->rx, netif->rx.req_cons++);
			meta = npo->meta + npo->meta_prod++;
			meta->gso_size = 0;
			meta->size = 0;
			meta->id = req->id;
			npo->copy_off = 0;
			npo->copy_gref = req->gref;
		}

		bytes = size;
		if (npo->copy_off + bytes > MAX_BUFFER_OFFSET)
			bytes = MAX_BUFFER_OFFSET - npo->copy_off;

		copy_gop = npo->copy + npo->copy_prod++;
		copy_gop->flags = GNTCOPY_dest_gref;
		if (foreign) {
			struct xen_netbk *netbk = &xen_netbk[group];
			struct pending_tx_info *src_pend;

			src_pend = &netbk->pending_tx_info[idx];

			copy_gop->source.domid = src_pend->netif->domid;
			copy_gop->source.u.ref = src_pend->req.gref;
			copy_gop->flags |= GNTCOPY_source_gref;
		} else {
			copy_gop->source.domid = DOMID_SELF;
			copy_gop->source.u.gmfn = virt_to_mfn(page_address(page));
		}
		copy_gop->source.offset = offset;
		copy_gop->dest.domid = netif->domid;

		copy_gop->dest.offset = npo->copy_off;
		copy_gop->dest.u.ref = npo->copy_gref;
		copy_gop->len = bytes;

		npo->copy_off += bytes;
		meta->size += bytes;

		offset += bytes;
		size -= bytes;
		head = 0; /* Must be something in this buffer now */
	}
}

/* Prepare an SKB to be transmitted to the frontend.  This is
   responsible for allocating grant operations, meta structures, etc.
   It returns the number of meta structures consumed.  The number of
   ring slots used is always equal to the number of meta slots used
   plus the number of GSO descriptors used.  Currently, we use either
   zero GSO descriptors (for non-GSO packets) or one descriptor (for
   frontend-side LRO). */
static int netbk_gop_skb(struct sk_buff *skb,
			 struct netrx_pending_operations *npo)
{
	struct xen_netif *netif = netdev_priv(skb->dev);
	int nr_frags = skb_shinfo(skb)->nr_frags;
	int i;
	struct xen_netif_rx_request *req;
	struct netbk_rx_meta *meta;
	int old_meta_prod;

	old_meta_prod = npo->meta_prod;

	/* Set up a GSO prefix descriptor, if necessary */
	if (skb_shinfo(skb)->gso_size && netif->gso_prefix) {
		req = RING_GET_REQUEST(&netif->rx, netif->rx.req_cons++);
		meta = npo->meta + npo->meta_prod++;
		meta->gso_size = skb_shinfo(skb)->gso_size;
		meta->size = 0;
		meta->id = req->id;
	}

	req = RING_GET_REQUEST(&netif->rx, netif->rx.req_cons++);
	meta = npo->meta + npo->meta_prod++;

	if (!netif->gso_prefix)
		meta->gso_size = skb_shinfo(skb)->gso_size;
	else
		meta->gso_size = 0;

	meta->size = 0;
	meta->id = req->id;
	npo->copy_off = 0;
	npo->copy_gref = req->gref;

	netbk_gop_frag_copy(netif,
			    npo, virt_to_page(skb->data),
			    skb_headlen(skb),
			    offset_in_page(skb->data), 1);

	/* Leave a gap for the GSO descriptor. */
	if (skb_shinfo(skb)->gso_size && !netif->gso_prefix)
		netif->rx.req_cons++;

	for (i = 0; i < nr_frags; i++) {
		netbk_gop_frag_copy(netif, npo,
				    skb_shinfo(skb)->frags[i].page,
				    skb_shinfo(skb)->frags[i].size,
				    skb_shinfo(skb)->frags[i].page_offset,
				    0);
	}

	return npo->meta_prod - old_meta_prod;
}

/* This is a twin to netbk_gop_skb.  Assume that netbk_gop_skb was
   used to set up the operations on the top of
   netrx_pending_operations, which have since been done.  Check that
   they didn't give any errors and advance over them. */
static int netbk_check_gop(int nr_meta_slots, domid_t domid,
			   struct netrx_pending_operations *npo)
{
	struct gnttab_copy     *copy_op;
	int status = NETIF_RSP_OKAY;
	int i;

	for (i = 0; i < nr_meta_slots; i++) {
		copy_op = npo->copy + npo->copy_cons++;
		if (copy_op->status != GNTST_okay) {
				DPRINTK("Bad status %d from copy to DOM%d.\n",
					copy_op->status, domid);
				status = NETIF_RSP_ERROR;
			}
	}

	return status;
}

static void netbk_add_frag_responses(struct xen_netif *netif, int status,
				     struct netbk_rx_meta *meta,
				     int nr_meta_slots)
{
	int i;
	unsigned long offset;

	for (i = 0; i < nr_meta_slots; i++) {
		int flags;
		if (i == nr_meta_slots - 1)
			flags = 0;
		else
			flags = NETRXF_more_data;

		offset = 0;
		make_rx_response(netif, meta[i].id, status, offset,
				 meta[i].size, flags);
	}
}

struct skb_cb_overlay {
	int meta_slots_used;
};

static void net_rx_action(unsigned long data)
{
	struct xen_netif *netif = NULL;
	struct xen_netbk *netbk = (struct xen_netbk *)data;
	s8 status;
	u16 irq, flags;
	struct xen_netif_rx_response *resp;
	struct sk_buff_head rxq;
	struct sk_buff *skb;
	int notify_nr = 0;
	int ret;
	int nr_frags;
	int count;
	unsigned long offset;
	struct skb_cb_overlay *sco;

	struct netrx_pending_operations npo = {
		.copy  = netbk->grant_copy_op,
		.meta  = netbk->meta,
	};

	skb_queue_head_init(&rxq);

	count = 0;

	while ((skb = skb_dequeue(&netbk->rx_queue)) != NULL) {
		netif = netdev_priv(skb->dev);
		nr_frags = skb_shinfo(skb)->nr_frags;

		sco = (struct skb_cb_overlay *)skb->cb;
		sco->meta_slots_used = netbk_gop_skb(skb, &npo);

		count += nr_frags + 1;

		__skb_queue_tail(&rxq, skb);

		/* Filled the batch queue? */
		if (count + MAX_SKB_FRAGS >= NET_RX_RING_SIZE)
			break;
	}

	BUG_ON(npo.meta_prod > ARRAY_SIZE(netbk->meta));

	if (!npo.copy_prod)
		return;

	BUG_ON(npo.copy_prod > ARRAY_SIZE(netbk->grant_copy_op));
	ret = HYPERVISOR_grant_table_op(GNTTABOP_copy, &netbk->grant_copy_op,
					npo.copy_prod);
	BUG_ON(ret != 0);

	while ((skb = __skb_dequeue(&rxq)) != NULL) {
		sco = (struct skb_cb_overlay *)skb->cb;

		netif = netdev_priv(skb->dev);

		if (netbk->meta[npo.meta_cons].gso_size && netif->gso_prefix) {
			resp = RING_GET_RESPONSE(&netif->rx,
						netif->rx.rsp_prod_pvt++);

			resp->flags = NETRXF_gso_prefix | NETRXF_more_data;

			resp->offset = netbk->meta[npo.meta_cons].gso_size;
			resp->id = netbk->meta[npo.meta_cons].id;
			resp->status = sco->meta_slots_used;

			npo.meta_cons++;
			sco->meta_slots_used--;
		}


		netif->stats.tx_bytes += skb->len;
		netif->stats.tx_packets++;

		status = netbk_check_gop(sco->meta_slots_used,
					 netif->domid, &npo);

		if (sco->meta_slots_used == 1)
			flags = 0;
		else
			flags = NETRXF_more_data;

		if (skb->ip_summed == CHECKSUM_PARTIAL) /* local packet? */
			flags |= NETRXF_csum_blank | NETRXF_data_validated;
		else if (skb->ip_summed == CHECKSUM_UNNECESSARY)
			/* remote but checksummed. */
			flags |= NETRXF_data_validated;

		offset = 0;
		resp = make_rx_response(netif, netbk->meta[npo.meta_cons].id,
					status, offset,
					netbk->meta[npo.meta_cons].size,
					flags);

		if (netbk->meta[npo.meta_cons].gso_size && !netif->gso_prefix) {
			struct xen_netif_extra_info *gso =
				(struct xen_netif_extra_info *)
				RING_GET_RESPONSE(&netif->rx,
						  netif->rx.rsp_prod_pvt++);

			resp->flags |= NETRXF_extra_info;

			gso->u.gso.size = netbk->meta[npo.meta_cons].gso_size;
			gso->u.gso.type = XEN_NETIF_GSO_TYPE_TCPV4;
			gso->u.gso.pad = 0;
			gso->u.gso.features = 0;

			gso->type = XEN_NETIF_EXTRA_TYPE_GSO;
			gso->flags = 0;
		}

		if (sco->meta_slots_used > 1) {
			netbk_add_frag_responses(netif, status,
						 netbk->meta + npo.meta_cons + 1,
						 sco->meta_slots_used - 1);
		}

		RING_PUSH_RESPONSES_AND_CHECK_NOTIFY(&netif->rx, ret);
		irq = netif->irq;
		if (ret && !netbk->rx_notify[irq] &&
				(netif->smart_poll != 1)) {
			netbk->rx_notify[irq] = 1;
			netbk->notify_list[notify_nr++] = irq;
		}

		if (netif_queue_stopped(netif->dev) &&
		    netif_schedulable(netif) &&
		    !netbk_queue_full(netif))
			netif_wake_queue(netif->dev);

		/*
		 * netfront_smartpoll_active indicates whether
		 * netfront timer is active.
		 */
		if ((netif->smart_poll == 1) &&
		    !(netif->rx.sring->private.netif.smartpoll_active)) {
			notify_remote_via_irq(irq);
			netif->rx.sring->private.netif.smartpoll_active = 1;
		}

		netif_put(netif);
		npo.meta_cons += sco->meta_slots_used;
		dev_kfree_skb(skb);
	}

	while (notify_nr != 0) {
		irq = netbk->notify_list[--notify_nr];
		netbk->rx_notify[irq] = 0;
		notify_remote_via_irq(irq);
	}

	/* More work to do? */
	if (!skb_queue_empty(&netbk->rx_queue) &&
			!timer_pending(&netbk->net_timer))
		xen_netbk_bh_handler(netbk, 1);
}

static void net_alarm(unsigned long data)
{
	struct xen_netbk *netbk = (struct xen_netbk *)data;
	xen_netbk_bh_handler(netbk, 1);
}

static void netbk_tx_pending_timeout(unsigned long data)
{
	struct xen_netbk *netbk = (struct xen_netbk *)data;
	xen_netbk_bh_handler(netbk, 0);
}

struct net_device_stats *netif_be_get_stats(struct net_device *dev)
{
	struct xen_netif *netif = netdev_priv(dev);
	return &netif->stats;
}

static int __on_net_schedule_list(struct xen_netif *netif)
{
	return !list_empty(&netif->list);
}

/* Must be called with net_schedule_list_lock held */
static void remove_from_net_schedule_list(struct xen_netif *netif)
{
	if (likely(__on_net_schedule_list(netif))) {
		list_del_init(&netif->list);
		netif_put(netif);
	}
}

static struct xen_netif *poll_net_schedule_list(struct xen_netbk *netbk)
{
	struct xen_netif *netif = NULL;

	spin_lock_irq(&netbk->net_schedule_list_lock);
	if (list_empty(&netbk->net_schedule_list))
		goto out;

	netif = list_first_entry(&netbk->net_schedule_list,
				 struct xen_netif, list);
	if (!netif)
		goto out;

	netif_get(netif);

	remove_from_net_schedule_list(netif);
out:
	spin_unlock_irq(&netbk->net_schedule_list_lock);
	return netif;
}

static void add_to_net_schedule_list_tail(struct xen_netif *netif)
{
	unsigned long flags;

	struct xen_netbk *netbk = &xen_netbk[netif->group];
	if (__on_net_schedule_list(netif))
		return;

	spin_lock_irqsave(&netbk->net_schedule_list_lock, flags);
	if (!__on_net_schedule_list(netif) &&
	    likely(netif_schedulable(netif))) {
		list_add_tail(&netif->list, &netbk->net_schedule_list);
		netif_get(netif);
	}
	spin_unlock_irqrestore(&netbk->net_schedule_list_lock, flags);
}

void netif_schedule_work(struct xen_netif *netif)
{
	struct xen_netbk *netbk = &xen_netbk[netif->group];
	int more_to_do;

	RING_FINAL_CHECK_FOR_REQUESTS(&netif->tx, more_to_do);

	if (more_to_do) {
		add_to_net_schedule_list_tail(netif);
		maybe_schedule_tx_action(netbk);
	}
}

void netif_deschedule_work(struct xen_netif *netif)
{
	struct xen_netbk *netbk = &xen_netbk[netif->group];
	spin_lock_irq(&netbk->net_schedule_list_lock);
	remove_from_net_schedule_list(netif);
	spin_unlock_irq(&netbk->net_schedule_list_lock);
}


static void tx_add_credit(struct xen_netif *netif)
{
	unsigned long max_burst, max_credit;

	/*
	 * Allow a burst big enough to transmit a jumbo packet of up to 128kB.
	 * Otherwise the interface can seize up due to insufficient credit.
	 */
	max_burst = RING_GET_REQUEST(&netif->tx, netif->tx.req_cons)->size;
	max_burst = min(max_burst, 131072UL);
	max_burst = max(max_burst, netif->credit_bytes);

	/* Take care that adding a new chunk of credit doesn't wrap to zero. */
	max_credit = netif->remaining_credit + netif->credit_bytes;
	if (max_credit < netif->remaining_credit)
		max_credit = ULONG_MAX; /* wrapped: clamp to ULONG_MAX */

	netif->remaining_credit = min(max_credit, max_burst);
}

static void tx_credit_callback(unsigned long data)
{
	struct xen_netif *netif = (struct xen_netif *)data;
	tx_add_credit(netif);
	netif_schedule_work(netif);
}

static inline int copy_pending_req(struct xen_netbk *netbk,
				   pending_ring_idx_t pending_idx)
{
	return gnttab_copy_grant_page(
			netbk->grant_tx_handle[pending_idx],
			&netbk->mmap_pages[pending_idx]);
}

static inline void net_tx_action_dealloc(struct xen_netbk *netbk)
{
	struct netbk_tx_pending_inuse *inuse, *n;
	struct gnttab_unmap_grant_ref *gop;
	u16 pending_idx;
	pending_ring_idx_t dc, dp;
	struct xen_netif *netif;
	int ret;
	LIST_HEAD(list);

	dc = netbk->dealloc_cons;
	gop = netbk->tx_unmap_ops;

	/*
	 * Free up any grants we have finished using
	 */
	do {
		dp = netbk->dealloc_prod;

		/* Ensure we see all indices enqueued by netif_idx_release(). */
		smp_rmb();

		while (dc != dp) {
			unsigned long pfn;
			struct netbk_tx_pending_inuse *pending_inuse =
					netbk->pending_inuse;

			pending_idx = netbk->dealloc_ring[pending_index(dc++)];
			list_move_tail(&pending_inuse[pending_idx].list, &list);

			pfn = idx_to_pfn(netbk, pending_idx);
			/* Already unmapped? */
			if (!phys_to_machine_mapping_valid(pfn))
				continue;

			gnttab_set_unmap_op(gop,
					idx_to_kaddr(netbk, pending_idx),
					GNTMAP_host_map,
					netbk->grant_tx_handle[pending_idx]);
			gop++;
		}

		if (netbk_copy_skb_mode != NETBK_DELAYED_COPY_SKB ||
		    list_empty(&netbk->pending_inuse_head))
			break;

		/* Copy any entries that have been pending for too long. */
		list_for_each_entry_safe(inuse, n,
				&netbk->pending_inuse_head, list) {
			struct pending_tx_info *pending_tx_info;
			pending_tx_info = netbk->pending_tx_info;

			if (time_after(inuse->alloc_time + HZ / 2, jiffies))
				break;

			pending_idx = inuse - netbk->pending_inuse;

			pending_tx_info[pending_idx].netif->nr_copied_skbs++;

			switch (copy_pending_req(netbk, pending_idx)) {
			case 0:
				list_move_tail(&inuse->list, &list);
				continue;
			case -EBUSY:
				list_del_init(&inuse->list);
				continue;
			case -ENOENT:
				continue;
			}

			break;
		}
	} while (dp != netbk->dealloc_prod);

	netbk->dealloc_cons = dc;

	ret = HYPERVISOR_grant_table_op(
		GNTTABOP_unmap_grant_ref, netbk->tx_unmap_ops,
		gop - netbk->tx_unmap_ops);
	BUG_ON(ret);

	list_for_each_entry_safe(inuse, n, &list, list) {
		struct pending_tx_info *pending_tx_info;
		pending_ring_idx_t index;

		pending_tx_info = netbk->pending_tx_info;
		pending_idx = inuse - netbk->pending_inuse;

		netif = pending_tx_info[pending_idx].netif;

		make_tx_response(netif, &pending_tx_info[pending_idx].req,
				 NETIF_RSP_OKAY);

		/* Ready for next use. */
		gnttab_reset_grant_page(netbk->mmap_pages[pending_idx]);

		index = pending_index(netbk->pending_prod++);
		netbk->pending_ring[index] = pending_idx;

		netif_put(netif);

		list_del_init(&inuse->list);
	}
}

static void netbk_tx_err(struct xen_netif *netif,
		struct xen_netif_tx_request *txp, RING_IDX end)
{
	RING_IDX cons = netif->tx.req_cons;

	do {
		make_tx_response(netif, txp, NETIF_RSP_ERROR);
		if (cons >= end)
			break;
		txp = RING_GET_REQUEST(&netif->tx, cons++);
	} while (1);
	netif->tx.req_cons = cons;
	netif_schedule_work(netif);
	netif_put(netif);
}

static int netbk_count_requests(struct xen_netif *netif,
				struct xen_netif_tx_request *first,
				struct xen_netif_tx_request *txp, int work_to_do)
{
	RING_IDX cons = netif->tx.req_cons;
	int frags = 0;

	if (!(first->flags & NETTXF_more_data))
		return 0;

	do {
		if (frags >= work_to_do) {
			DPRINTK("Need more frags\n");
			return -frags;
		}

		if (unlikely(frags >= MAX_SKB_FRAGS)) {
			DPRINTK("Too many frags\n");
			return -frags;
		}

		memcpy(txp, RING_GET_REQUEST(&netif->tx, cons + frags),
		       sizeof(*txp));
		if (txp->size > first->size) {
			DPRINTK("Frags galore\n");
			return -frags;
		}

		first->size -= txp->size;
		frags++;

		if (unlikely((txp->offset + txp->size) > PAGE_SIZE)) {
			DPRINTK("txp->offset: %x, size: %u\n",
				txp->offset, txp->size);
			return -frags;
		}
	} while ((txp++)->flags & NETTXF_more_data);

	return frags;
}

static struct gnttab_map_grant_ref *netbk_get_requests(struct xen_netbk *netbk,
						  struct xen_netif *netif,
						  struct sk_buff *skb,
						  struct xen_netif_tx_request *txp,
						  struct gnttab_map_grant_ref *mop)
{
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	skb_frag_t *frags = shinfo->frags;
	unsigned long pending_idx = *((u16 *)skb->data);
	int i, start;

	/* Skip first skb fragment if it is on same page as header fragment. */
	start = ((unsigned long)shinfo->frags[0].page == pending_idx);

	for (i = start; i < shinfo->nr_frags; i++, txp++) {
		pending_ring_idx_t index;
		struct pending_tx_info *pending_tx_info =
			netbk->pending_tx_info;

		index = pending_index(netbk->pending_cons++);
		pending_idx = netbk->pending_ring[index];

		gnttab_set_map_op(mop++, idx_to_kaddr(netbk, pending_idx),
				  GNTMAP_host_map | GNTMAP_readonly,
				  txp->gref, netif->domid);

		memcpy(&pending_tx_info[pending_idx].req, txp, sizeof(*txp));
		netif_get(netif);
		pending_tx_info[pending_idx].netif = netif;
		frags[i].page = (void *)pending_idx;
	}

	return mop;
}

static int netbk_tx_check_mop(struct xen_netbk *netbk,
			      struct sk_buff *skb,
			      struct gnttab_map_grant_ref **mopp)
{
	struct gnttab_map_grant_ref *mop = *mopp;
	int pending_idx = *((u16 *)skb->data);
	struct pending_tx_info *pending_tx_info = netbk->pending_tx_info;
	struct xen_netif *netif = pending_tx_info[pending_idx].netif;
	struct xen_netif_tx_request *txp;
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	int nr_frags = shinfo->nr_frags;
	int i, err, start;

	/* Check status of header. */
	err = mop->status;
	if (unlikely(err)) {
		pending_ring_idx_t index;
		index = pending_index(netbk->pending_prod++);
		txp = &pending_tx_info[pending_idx].req;
		make_tx_response(netif, txp, NETIF_RSP_ERROR);
		netbk->pending_ring[index] = pending_idx;
		netif_put(netif);
	} else {
		set_phys_to_machine(
			__pa(idx_to_kaddr(netbk, pending_idx)) >> PAGE_SHIFT,
			FOREIGN_FRAME(mop->dev_bus_addr >> PAGE_SHIFT));
		netbk->grant_tx_handle[pending_idx] = mop->handle;
	}

	/* Skip first skb fragment if it is on same page as header fragment. */
	start = ((unsigned long)shinfo->frags[0].page == pending_idx);

	for (i = start; i < nr_frags; i++) {
		int j, newerr;
		pending_ring_idx_t index;

		pending_idx = (unsigned long)shinfo->frags[i].page;

		/* Check error status: if okay then remember grant handle. */
		newerr = (++mop)->status;
		if (likely(!newerr)) {
			unsigned long addr;
			addr = idx_to_kaddr(netbk, pending_idx);
			set_phys_to_machine(
				__pa(addr)>>PAGE_SHIFT,
				FOREIGN_FRAME(mop->dev_bus_addr>>PAGE_SHIFT));
			netbk->grant_tx_handle[pending_idx] = mop->handle;
			/* Had a previous error? Invalidate this fragment. */
			if (unlikely(err))
				netif_idx_release(netbk, pending_idx);
			continue;
		}

		/* Error on this fragment: respond to client with an error. */
		txp = &netbk->pending_tx_info[pending_idx].req;
		make_tx_response(netif, txp, NETIF_RSP_ERROR);
		index = pending_index(netbk->pending_prod++);
		netbk->pending_ring[index] = pending_idx;
		netif_put(netif);

		/* Not the first error? Preceding frags already invalidated. */
		if (err)
			continue;

		/* First error: invalidate header and preceding fragments. */
		pending_idx = *((u16 *)skb->data);
		netif_idx_release(netbk, pending_idx);
		for (j = start; j < i; j++) {
			pending_idx = (unsigned long)shinfo->frags[i].page;
			netif_idx_release(netbk, pending_idx);
		}

		/* Remember the error: invalidate all subsequent fragments. */
		err = newerr;
	}

	*mopp = mop + 1;
	return err;
}

static void netbk_fill_frags(struct xen_netbk *netbk, struct sk_buff *skb)
{
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	int nr_frags = shinfo->nr_frags;
	int i;

	for (i = 0; i < nr_frags; i++) {
		skb_frag_t *frag = shinfo->frags + i;
		struct xen_netif_tx_request *txp;
		unsigned long pending_idx;

		pending_idx = (unsigned long)frag->page;

		netbk->pending_inuse[pending_idx].alloc_time = jiffies;
		list_add_tail(&netbk->pending_inuse[pending_idx].list,
			      &netbk->pending_inuse_head);

		txp = &netbk->pending_tx_info[pending_idx].req;
		frag->page = virt_to_page(idx_to_kaddr(netbk, pending_idx));
		frag->size = txp->size;
		frag->page_offset = txp->offset;

		skb->len += txp->size;
		skb->data_len += txp->size;
		skb->truesize += txp->size;
	}
}

int netbk_get_extras(struct xen_netif *netif, struct xen_netif_extra_info *extras,
		     int work_to_do)
{
	struct xen_netif_extra_info extra;
	RING_IDX cons = netif->tx.req_cons;

	do {
		if (unlikely(work_to_do-- <= 0)) {
			DPRINTK("Missing extra info\n");
			return -EBADR;
		}

		memcpy(&extra, RING_GET_REQUEST(&netif->tx, cons),
		       sizeof(extra));
		if (unlikely(!extra.type ||
			     extra.type >= XEN_NETIF_EXTRA_TYPE_MAX)) {
			netif->tx.req_cons = ++cons;
			DPRINTK("Invalid extra type: %d\n", extra.type);
			return -EINVAL;
		}

		memcpy(&extras[extra.type - 1], &extra, sizeof(extra));
		netif->tx.req_cons = ++cons;
	} while (extra.flags & XEN_NETIF_EXTRA_FLAG_MORE);

	return work_to_do;
}

static int netbk_set_skb_gso(struct sk_buff *skb, struct xen_netif_extra_info *gso)
{
	if (!gso->u.gso.size) {
		DPRINTK("GSO size must not be zero.\n");
		return -EINVAL;
	}

	/* Currently only TCPv4 S.O. is supported. */
	if (gso->u.gso.type != XEN_NETIF_GSO_TYPE_TCPV4) {
		DPRINTK("Bad GSO type %d.\n", gso->u.gso.type);
		return -EINVAL;
	}

	skb_shinfo(skb)->gso_size = gso->u.gso.size;
	skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;

	/* Header must be checked, and gso_segs computed. */
	skb_shinfo(skb)->gso_type |= SKB_GSO_DODGY;
	skb_shinfo(skb)->gso_segs = 0;

	return 0;
}

static int skb_checksum_setup(struct sk_buff *skb)
{
	struct iphdr *iph;
	unsigned char *th;
	int err = -EPROTO;

	if (skb->protocol != htons(ETH_P_IP))
		goto out;

	iph = (void *)skb->data;
	th = skb->data + 4 * iph->ihl;
	if (th >= skb_tail_pointer(skb))
		goto out;

	skb->csum_start = th - skb->head;
	switch (iph->protocol) {
	case IPPROTO_TCP:
		skb->csum_offset = offsetof(struct tcphdr, check);
		break;
	case IPPROTO_UDP:
		skb->csum_offset = offsetof(struct udphdr, check);
		break;
	default:
		if (net_ratelimit())
			printk(KERN_ERR "Attempting to checksum a non-"
			       "TCP/UDP packet, dropping a protocol"
			       " %d packet", iph->protocol);
		goto out;
	}

	if ((th + skb->csum_offset + 2) > skb_tail_pointer(skb))
		goto out;

	err = 0;

out:
	return err;
}

static bool tx_credit_exceeded(struct xen_netif *netif, unsigned size)
{
	unsigned long now = jiffies;
	unsigned long next_credit =
		netif->credit_timeout.expires +
		msecs_to_jiffies(netif->credit_usec / 1000);

	/* Timer could already be pending in rare cases. */
	if (timer_pending(&netif->credit_timeout))
		return true;

	/* Passed the point where we can replenish credit? */
	if (time_after_eq(now, next_credit)) {
		netif->credit_timeout.expires = now;
		tx_add_credit(netif);
	}

	/* Still too big to send right now? Set a callback. */
	if (size > netif->remaining_credit) {
		netif->credit_timeout.data     =
			(unsigned long)netif;
		netif->credit_timeout.function =
			tx_credit_callback;
		mod_timer(&netif->credit_timeout,
			  next_credit);

		return true;
	}

	return false;
}

static unsigned net_tx_build_mops(struct xen_netbk *netbk)
{
	struct gnttab_map_grant_ref *mop;
	struct sk_buff *skb;
	int ret;

	mop = netbk->tx_map_ops;
	while (((nr_pending_reqs(netbk) + MAX_SKB_FRAGS) < MAX_PENDING_REQS) &&
		!list_empty(&netbk->net_schedule_list)) {
		struct xen_netif *netif;
		struct xen_netif_tx_request txreq;
		struct xen_netif_tx_request txfrags[MAX_SKB_FRAGS];
		struct xen_netif_extra_info extras[XEN_NETIF_EXTRA_TYPE_MAX - 1];
		u16 pending_idx;
		RING_IDX idx;
		int work_to_do;
		unsigned int data_len;
		pending_ring_idx_t index;

		/* Get a netif from the list with work to do. */
		netif = poll_net_schedule_list(netbk);
		if (!netif)
			continue;

		RING_FINAL_CHECK_FOR_REQUESTS(&netif->tx, work_to_do);
		if (!work_to_do) {
			netif_put(netif);
			continue;
		}

		idx = netif->tx.req_cons;
		rmb(); /* Ensure that we see the request before we copy it. */
		memcpy(&txreq, RING_GET_REQUEST(&netif->tx, idx), sizeof(txreq));

		/* Credit-based scheduling. */
		if (txreq.size > netif->remaining_credit &&
		    tx_credit_exceeded(netif, txreq.size)) {
			netif_put(netif);
			continue;
		}

		netif->remaining_credit -= txreq.size;

		work_to_do--;
		netif->tx.req_cons = ++idx;

		memset(extras, 0, sizeof(extras));
		if (txreq.flags & NETTXF_extra_info) {
			work_to_do = netbk_get_extras(netif, extras,
						      work_to_do);
			idx = netif->tx.req_cons;
			if (unlikely(work_to_do < 0)) {
				netbk_tx_err(netif, &txreq, idx);
				continue;
			}
		}

		ret = netbk_count_requests(netif, &txreq, txfrags, work_to_do);
		if (unlikely(ret < 0)) {
			netbk_tx_err(netif, &txreq, idx - ret);
			continue;
		}
		idx += ret;

		if (unlikely(txreq.size < ETH_HLEN)) {
			DPRINTK("Bad packet size: %d\n", txreq.size);
			netbk_tx_err(netif, &txreq, idx);
			continue;
		}

		/* No crossing a page as the payload mustn't fragment. */
		if (unlikely((txreq.offset + txreq.size) > PAGE_SIZE)) {
			DPRINTK("txreq.offset: %x, size: %u, end: %lu\n",
				txreq.offset, txreq.size,
				(txreq.offset &~PAGE_MASK) + txreq.size);
			netbk_tx_err(netif, &txreq, idx);
			continue;
		}

		index = pending_index(netbk->pending_cons);
		pending_idx = netbk->pending_ring[index];

		data_len = (txreq.size > PKT_PROT_LEN &&
			    ret < MAX_SKB_FRAGS) ?
			PKT_PROT_LEN : txreq.size;

		skb = alloc_skb(data_len + NET_SKB_PAD + NET_IP_ALIGN,
				GFP_ATOMIC | __GFP_NOWARN);
		if (unlikely(skb == NULL)) {
			DPRINTK("Can't allocate a skb in start_xmit.\n");
			netbk_tx_err(netif, &txreq, idx);
			break;
		}

		/* Packets passed to netif_rx() must have some headroom. */
		skb_reserve(skb, NET_SKB_PAD + NET_IP_ALIGN);

		if (extras[XEN_NETIF_EXTRA_TYPE_GSO - 1].type) {
			struct xen_netif_extra_info *gso;
			gso = &extras[XEN_NETIF_EXTRA_TYPE_GSO - 1];

			if (netbk_set_skb_gso(skb, gso)) {
				kfree_skb(skb);
				netbk_tx_err(netif, &txreq, idx);
				continue;
			}
		}

		gnttab_set_map_op(mop, idx_to_kaddr(netbk, pending_idx),
				  GNTMAP_host_map | GNTMAP_readonly,
				  txreq.gref, netif->domid);
		mop++;

		memcpy(&netbk->pending_tx_info[pending_idx].req,
		       &txreq, sizeof(txreq));
		netbk->pending_tx_info[pending_idx].netif = netif;
		*((u16 *)skb->data) = pending_idx;

		__skb_put(skb, data_len);

		skb_shinfo(skb)->nr_frags = ret;
		if (data_len < txreq.size) {
			skb_shinfo(skb)->nr_frags++;
			skb_shinfo(skb)->frags[0].page =
				(void *)(unsigned long)pending_idx;
		} else {
			/* Discriminate from any valid pending_idx value. */
			skb_shinfo(skb)->frags[0].page = (void *)~0UL;
		}

		__skb_queue_tail(&netbk->tx_queue, skb);

		netbk->pending_cons++;

		mop = netbk_get_requests(netbk, netif, skb, txfrags, mop);

		netif->tx.req_cons = idx;
		netif_schedule_work(netif);

		if ((mop - netbk->tx_map_ops) >= ARRAY_SIZE(netbk->tx_map_ops))
			break;
	}

	return mop - netbk->tx_map_ops;
}

static void net_tx_submit(struct xen_netbk *netbk)
{
	struct gnttab_map_grant_ref *mop;
	struct sk_buff *skb;

	mop = netbk->tx_map_ops;
	while ((skb = __skb_dequeue(&netbk->tx_queue)) != NULL) {
		struct xen_netif_tx_request *txp;
		struct xen_netif *netif;
		u16 pending_idx;
		unsigned data_len;

		pending_idx = *((u16 *)skb->data);
		netif = netbk->pending_tx_info[pending_idx].netif;
		txp = &netbk->pending_tx_info[pending_idx].req;

		/* Check the remap error code. */
		if (unlikely(netbk_tx_check_mop(netbk, skb, &mop))) {
			DPRINTK("netback grant failed.\n");
			skb_shinfo(skb)->nr_frags = 0;
			kfree_skb(skb);
			continue;
		}

		data_len = skb->len;
		memcpy(skb->data,
		       (void *)(idx_to_kaddr(netbk, pending_idx)|txp->offset),
		       data_len);
		if (data_len < txp->size) {
			/* Append the packet payload as a fragment. */
			txp->offset += data_len;
			txp->size -= data_len;
		} else {
			/* Schedule a response immediately. */
			netif_idx_release(netbk, pending_idx);
		}

		if (txp->flags & NETTXF_csum_blank)
			skb->ip_summed = CHECKSUM_PARTIAL;
		else if (txp->flags & NETTXF_data_validated)
			skb->ip_summed = CHECKSUM_UNNECESSARY;

		netbk_fill_frags(netbk, skb);

		/*
		 * If the initial fragment was < PKT_PROT_LEN then
		 * pull through some bytes from the other fragments to
		 * increase the linear region to PKT_PROT_LEN bytes.
		 */
		if (skb_headlen(skb) < PKT_PROT_LEN && skb_is_nonlinear(skb)) {
			int target = min_t(int, skb->len, PKT_PROT_LEN);
			__pskb_pull_tail(skb, target - skb_headlen(skb));
		}

		skb->dev      = netif->dev;
		skb->protocol = eth_type_trans(skb, skb->dev);

		netif->stats.rx_bytes += skb->len;
		netif->stats.rx_packets++;

		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			if (skb_checksum_setup(skb)) {
				DPRINTK("Can't setup checksum in net_tx_action\n");
				kfree_skb(skb);
				continue;
			}
		}

		if (unlikely(netbk_copy_skb_mode == NETBK_ALWAYS_COPY_SKB) &&
		    unlikely(skb_linearize(skb))) {
			DPRINTK("Can't linearize skb in net_tx_action.\n");
			kfree_skb(skb);
			continue;
		}

		netif_rx_ni(skb);
		netif->dev->last_rx = jiffies;
	}
}

/* Called after netfront has transmitted */
static void net_tx_action(unsigned long data)
{
	struct xen_netbk *netbk = (struct xen_netbk *)data;
	unsigned nr_mops;
	int ret;

	net_tx_action_dealloc(netbk);

	nr_mops = net_tx_build_mops(netbk);

	if (nr_mops == 0)
		goto out;

	ret = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref,
					netbk->tx_map_ops, nr_mops);
	BUG_ON(ret);

	net_tx_submit(netbk);
out:
	if (netbk_copy_skb_mode == NETBK_DELAYED_COPY_SKB &&
	    !list_empty(&netbk->pending_inuse_head)) {
		struct netbk_tx_pending_inuse *oldest;

		oldest = list_entry(netbk->pending_inuse_head.next,
				    struct netbk_tx_pending_inuse, list);
		mod_timer(&netbk->netbk_tx_pending_timer,
				oldest->alloc_time + HZ);
	}
}

static void netif_idx_release(struct xen_netbk *netbk, u16 pending_idx)
{
	static DEFINE_SPINLOCK(_lock);
	unsigned long flags;
	pending_ring_idx_t index;

	spin_lock_irqsave(&_lock, flags);
	index = pending_index(netbk->dealloc_prod);
	netbk->dealloc_ring[index] = pending_idx;
	/* Sync with net_tx_action_dealloc: insert idx /then/ incr producer. */
	smp_wmb();
	netbk->dealloc_prod++;
	spin_unlock_irqrestore(&_lock, flags);

	xen_netbk_bh_handler(netbk, 0);
}

static void netif_page_release(struct page *page, unsigned int order)
{
	unsigned int group, idx;
	int foreign = netif_get_page_ext(page, &group, &idx);

	BUG_ON(!foreign);
	BUG_ON(order);

	netif_idx_release(&xen_netbk[group], idx);
}

irqreturn_t netif_be_int(int irq, void *dev_id)
{
	struct xen_netif *netif = dev_id;
	struct xen_netbk *netbk;

	if (netif->group == -1)
		return IRQ_NONE;

	netbk = &xen_netbk[netif->group];

	add_to_net_schedule_list_tail(netif);
	maybe_schedule_tx_action(netbk);

	if (netif_schedulable(netif) && !netbk_queue_full(netif))
		netif_wake_queue(netif->dev);

	return IRQ_HANDLED;
}

static void make_tx_response(struct xen_netif *netif,
			     struct xen_netif_tx_request *txp,
			     s8       st)
{
	RING_IDX i = netif->tx.rsp_prod_pvt;
	struct xen_netif_tx_response *resp;
	int notify;

	resp = RING_GET_RESPONSE(&netif->tx, i);
	resp->id     = txp->id;
	resp->status = st;

	if (txp->flags & NETTXF_extra_info)
		RING_GET_RESPONSE(&netif->tx, ++i)->status = NETIF_RSP_NULL;

	netif->tx.rsp_prod_pvt = ++i;
	RING_PUSH_RESPONSES_AND_CHECK_NOTIFY(&netif->tx, notify);

	/*
	 * netfront_smartpoll_active indicates whether netfront timer
	 * is active.
	 */
	if ((netif->smart_poll == 1)) {
		if (!(netif->rx.sring->private.netif.smartpoll_active)) {
			notify_remote_via_irq(netif->irq);
			netif->rx.sring->private.netif.smartpoll_active = 1;
		}
	} else if (notify)
		notify_remote_via_irq(netif->irq);
}

static struct xen_netif_rx_response *make_rx_response(struct xen_netif *netif,
					     u16      id,
					     s8       st,
					     u16      offset,
					     u16      size,
					     u16      flags)
{
	RING_IDX i = netif->rx.rsp_prod_pvt;
	struct xen_netif_rx_response *resp;

	resp = RING_GET_RESPONSE(&netif->rx, i);
	resp->offset     = offset;
	resp->flags      = flags;
	resp->id         = id;
	resp->status     = (s16)size;
	if (st < 0)
		resp->status = (s16)st;

	netif->rx.rsp_prod_pvt = ++i;

	return resp;
}

#ifdef NETBE_DEBUG_INTERRUPT
static irqreturn_t netif_be_dbg(int irq, void *dev_id, struct pt_regs *regs)
{
	struct list_head *ent;
	struct xen_netif *netif;
	int i = 0;
	int group = 0;

	printk(KERN_ALERT "netif_schedule_list:\n");

	for (group = 0; group < xen_netbk_group_nr; group++) {
		struct xen_netbk *netbk = &xen_netbk[group];
		spin_lock_irq(&netbk->net_schedule_list_lock);
		printk(KERN_ALERT "xen_netback group number: %d\n", group);
		list_for_each(ent, &netbk->net_schedule_list) {
			netif = list_entry(ent, struct xen_netif, list);
			printk(KERN_ALERT " %d: private(rx_req_cons=%08x "
				"rx_resp_prod=%08x\n",
				i, netif->rx.req_cons, netif->rx.rsp_prod_pvt);
			printk(KERN_ALERT
				"   tx_req_cons=%08x, tx_resp_prod=%08x)\n",
				netif->tx.req_cons, netif->tx.rsp_prod_pvt);
			printk(KERN_ALERT
				"   shared(rx_req_prod=%08x "
				"rx_resp_prod=%08x\n",
				netif->rx.sring->req_prod,
				netif->rx.sring->rsp_prod);
			printk(KERN_ALERT
				"   rx_event=%08x, tx_req_prod=%08x\n",
				netif->rx.sring->rsp_event,
				netif->tx.sring->req_prod);
			printk(KERN_ALERT
				"   tx_resp_prod=%08x, tx_event=%08x)\n",
				netif->tx.sring->rsp_prod,
				netif->tx.sring->rsp_event);
			i++;
		}
		spin_unlock_irq(&netbk->net_schedule_list_lock);
	}

	printk(KERN_ALERT " ** End of netif_schedule_list **\n");

	return IRQ_HANDLED;
}
#endif

static inline int rx_work_todo(struct xen_netbk *netbk)
{
	return !skb_queue_empty(&netbk->rx_queue);
}

static inline int tx_work_todo(struct xen_netbk *netbk)
{
	if (netbk->dealloc_cons != netbk->dealloc_prod)
		return 1;

	if (((nr_pending_reqs(netbk) + MAX_SKB_FRAGS) < MAX_PENDING_REQS) &&
			!list_empty(&netbk->net_schedule_list))
		return 1;

	return 0;
}

static int netbk_action_thread(void *data)
{
	struct xen_netbk *netbk = (struct xen_netbk *)data;
	while (!kthread_should_stop()) {
		wait_event_interruptible(netbk->kthread.netbk_action_wq,
				rx_work_todo(netbk)
				|| tx_work_todo(netbk)
				|| kthread_should_stop());
		cond_resched();

		if (kthread_should_stop())
			break;

		if (rx_work_todo(netbk))
			net_rx_action((unsigned long)netbk);

		if (tx_work_todo(netbk))
			net_tx_action((unsigned long)netbk);
	}

	return 0;
}

static int __init netback_init(void)
{
	int i;
	struct page *page;
	int rc = 0;
	int group;

	if (!xen_pv_domain())
		return -ENODEV;

	xen_netbk_group_nr = num_online_cpus();
	xen_netbk = vmalloc(sizeof(struct xen_netbk) * xen_netbk_group_nr);
	if (!xen_netbk) {
		printk(KERN_ALERT "%s: out of memory\n", __func__);
		return -ENOMEM;
	}
	memset(xen_netbk, 0, sizeof(struct xen_netbk) * xen_netbk_group_nr);

	/* We can increase reservation by this much in net_rx_action(). */
//	balloon_update_driver_allowance(NET_RX_RING_SIZE);

	for (group = 0; group < xen_netbk_group_nr; group++) {
		struct xen_netbk *netbk = &xen_netbk[group];
		skb_queue_head_init(&netbk->rx_queue);
		skb_queue_head_init(&netbk->tx_queue);

		init_timer(&netbk->net_timer);
		netbk->net_timer.data = (unsigned long)netbk;
		netbk->net_timer.function = net_alarm;

		init_timer(&netbk->netbk_tx_pending_timer);
		netbk->netbk_tx_pending_timer.data = (unsigned long)netbk;
		netbk->netbk_tx_pending_timer.function =
			netbk_tx_pending_timeout;

		netbk->mmap_pages =
			alloc_empty_pages_and_pagevec(MAX_PENDING_REQS);
		if (!netbk->mmap_pages) {
			printk(KERN_ALERT "%s: out of memory\n", __func__);
			del_timer(&netbk->netbk_tx_pending_timer);
			del_timer(&netbk->net_timer);
			rc = -ENOMEM;
			goto failed_init;
		}

		for (i = 0; i < MAX_PENDING_REQS; i++) {
			page = netbk->mmap_pages[i];
			SetPageForeign(page, netif_page_release);
			netif_set_page_ext(page, group, i);
			INIT_LIST_HEAD(&netbk->pending_inuse[i].list);
		}

		netbk->pending_cons = 0;
		netbk->pending_prod = MAX_PENDING_REQS;
		for (i = 0; i < MAX_PENDING_REQS; i++)
			netbk->pending_ring[i] = i;

		if (MODPARM_netback_kthread) {
			init_waitqueue_head(&netbk->kthread.netbk_action_wq);
			netbk->kthread.task =
				kthread_create(netbk_action_thread,
					       (void *)netbk,
					       "netback/%u", group);

			if (!IS_ERR(netbk->kthread.task)) {
				kthread_bind(netbk->kthread.task, group);
			} else {
				printk(KERN_ALERT
					"kthread_run() fails at netback\n");
				free_empty_pages_and_pagevec(netbk->mmap_pages,
						MAX_PENDING_REQS);
				del_timer(&netbk->netbk_tx_pending_timer);
				del_timer(&netbk->net_timer);
				rc = PTR_ERR(netbk->kthread.task);
				goto failed_init;
			}
		} else {
			tasklet_init(&netbk->tasklet.net_tx_tasklet,
				     net_tx_action,
				     (unsigned long)netbk);
			tasklet_init(&netbk->tasklet.net_rx_tasklet,
				     net_rx_action,
				     (unsigned long)netbk);
		}

		INIT_LIST_HEAD(&netbk->pending_inuse_head);
		INIT_LIST_HEAD(&netbk->net_schedule_list);

		spin_lock_init(&netbk->net_schedule_list_lock);

		atomic_set(&netbk->netfront_count, 0);

		if (MODPARM_netback_kthread)
			wake_up_process(netbk->kthread.task);
	}

	netbk_copy_skb_mode = NETBK_DONT_COPY_SKB;
	if (MODPARM_copy_skb) {
		if (HYPERVISOR_grant_table_op(GNTTABOP_unmap_and_replace,
					      NULL, 0))
			netbk_copy_skb_mode = NETBK_ALWAYS_COPY_SKB;
		else
			netbk_copy_skb_mode = NETBK_DELAYED_COPY_SKB;
	}

	//netif_accel_init();

	rc = netif_xenbus_init();
	if (rc)
		goto failed_init;

#ifdef NETBE_DEBUG_INTERRUPT
	(void)bind_virq_to_irqhandler(VIRQ_DEBUG,
				      0,
				      netif_be_dbg,
				      IRQF_SHARED,
				      "net-be-dbg",
				      &netif_be_dbg);
#endif

	return 0;

failed_init:
	for (i = 0; i < group; i++) {
		struct xen_netbk *netbk = &xen_netbk[i];
		free_empty_pages_and_pagevec(netbk->mmap_pages,
				MAX_PENDING_REQS);
		del_timer(&netbk->netbk_tx_pending_timer);
		del_timer(&netbk->net_timer);
		if (MODPARM_netback_kthread)
			kthread_stop(netbk->kthread.task);
	}
	vfree(xen_netbk);
	return rc;

}

module_init(netback_init);

MODULE_LICENSE("Dual BSD/GPL");
