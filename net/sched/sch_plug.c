/*
 * sch_plug.c Queue traffic until an explicit release command
 *
 *             This program is free software; you can redistribute it and/or
 *             modify it under the terms of the GNU General Public License
 *             as published by the Free Software Foundation; either version
 *             2 of the License, or (at your option) any later version.
 *
 * The operation of the buffer is as follows:
 * When a checkpoint begins, a plug is inserted into the
 *   network queue by a netlink request (it operates by storing
 *   a pointer to the next packet which arrives and blocking dequeue
 *   when that packet is at the head of the queue).
 * When a checkpoint completes (the backup acknowledges receipt),
 *   currently-queued packets are released.
 * So it supports two operations, plug and unplug.
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>

#define FIFO_BUF    (10*1024*1024)

#define TCQ_PLUG   0
#define TCQ_UNPLUG 1

struct plug_sched_data {
	/*
	 * This packet is the first packet which should not be
	 * delivered.  If it is NULL, plug_enqueue will set it to the
	 * next packet it sees.
	 */
	struct sk_buff *stop;
};

struct tc_plug_qopt {
	/* 0: reset stop packet pointer
	 * 1: dequeue to stop pointer */
	int action;
};

static int skb_remove_foreign_references(struct sk_buff *skb)
{
	return !skb_linearize(skb);
}

static int plug_enqueue(struct sk_buff *skb, struct Qdisc* sch)
{
	struct plug_sched_data *q = qdisc_priv(sch);

	if (likely(sch->qstats.backlog + skb->len <= FIFO_BUF)) {
		if (!q->stop)
			q->stop = skb;

		if (!skb_remove_foreign_references(skb)) {
			printk(KERN_DEBUG "error removing foreign ref\n");
			return qdisc_reshape_fail(skb, sch);
		}

		return qdisc_enqueue_tail(skb, sch);
	}
	printk(KERN_WARNING "queue reported full: %d,%d\n",
	       sch->qstats.backlog, skb->len);

	return qdisc_reshape_fail(skb, sch);
}

/* dequeue doesn't actually dequeue until the release command is
 * received. */
static struct sk_buff *plug_dequeue(struct Qdisc* sch)
{
	struct plug_sched_data *q = qdisc_priv(sch);
	struct sk_buff *peek;

	if (sch->flags & TCQ_F_THROTTLED)
		return NULL;

	peek = (struct sk_buff *)((sch->q).next);

	/* this pointer comparison may be shady */
	if (peek == q->stop) {
		/*
		 * This is the tail of the last round. Release it and
		 * block the queue
		 */
		sch->flags |= TCQ_F_THROTTLED;
		return NULL;
	}

	return qdisc_dequeue_head(sch);
}

static int plug_init(struct Qdisc *sch, struct nlattr *opt)
{
	sch->flags |= TCQ_F_THROTTLED;

	return 0;
}

/*
 * receives two messages:
 *   0: checkpoint queue (set stop to next packet)
 *   1: dequeue until stop
 */
static int plug_change(struct Qdisc *sch, struct nlattr *opt)
{
	struct plug_sched_data *q = qdisc_priv(sch);
	struct tc_plug_qopt *msg;

	if (!opt || nla_len(opt) < sizeof(*msg))
		return -EINVAL;

	msg = nla_data(opt);

	if (msg->action == TCQ_PLUG) {
		/* reset stop */
		q->stop = NULL;
	} else if (msg->action == TCQ_UNPLUG) {
		/* dequeue */
		sch->flags &= ~TCQ_F_THROTTLED;
		netif_schedule_queue(sch->dev_queue);
	} else {
		return -EINVAL;
	}

	return 0;
}

struct Qdisc_ops plug_qdisc_ops = {
	.id          =       "plug",
	.priv_size   =       sizeof(struct plug_sched_data),
	.enqueue     =       plug_enqueue,
	.dequeue     =       plug_dequeue,
	.peek        =       qdisc_peek_head,
	.init        =       plug_init,
	.change      =       plug_change,
	.owner       =       THIS_MODULE,
};

static int __init plug_module_init(void)
{
	return register_qdisc(&plug_qdisc_ops);
}

static void __exit plug_module_exit(void)
{
	unregister_qdisc(&plug_qdisc_ops);
}
module_init(plug_module_init)
module_exit(plug_module_exit)
MODULE_LICENSE("GPL");
