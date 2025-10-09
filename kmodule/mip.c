/*
 *	pep-dna/kmodule/mip.c: PEP-DNA MIP implementation
 *
 *	Copyright (C) 2025	Kristjon Ciko <kristjoc@ifi.uio.no>
 *
 *	This program is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <net/ip.h>
#include <net/route.h>
#include <linux/netdevice.h>

#include "mip.h"
#include "core.h"
#include "connection.h"
#include "hash.h"
#include "tcp_utils.h"

extern char *ifname; /* Declared in 'core.c' */

/* Current MTU of interface 'ifname'. */
#define MIP_MTU (READ_ONCE(__dev_get_by_name(&init_net, ifname)->mtu))
/* Size of the MIP protocol header. */
#define MIP_HDR_LEN (sizeof(struct miphdr))
/* Max payload (MTU minus header size). */
#define MIP_MSS (MIP_MTU - MIP_HDR_LEN)
/* Initial cwnd in bytes */
#define MIP_INIT_CWND_BYTES (MIP_INIT_CWND * MIP_MSS)
/* Send window size (~1Mb) */
#define WINDOW_SIZE (((512u * 1024) / MIP_MSS) * MIP_MSS)
#define MIP_MAX_CWND_PKTS ((512u * 1024) / MIP_MSS)


/**
 * skb_get_seq - Retrieve sequence number from skb
 * @skb: Pointer to skb
 *
 * Returns the u32 sequence number from the miphdr in host order.
 */
static u32 skb_get_seq(struct sk_buff *skb)
{
	struct miphdr *hdr = (struct miphdr *)skb_network_header(skb);

	return ntohl(hdr->seq);
}


/**
 * find_skb_by_seq - Find first SKB in a list with matching sequence number
 * @list: SKB queue to search
 * @seq: Sequence number to find (host byte order)
 *
 * Returns: pointer to matching SKB or NULL if not found.
 */
static struct sk_buff *find_skb_by_seq(struct sk_buff_head *list, u32 seq)
{
	struct sk_buff *skb;

	skb_queue_walk(list, skb)
	{
		if (skb_get_seq(skb) == seq)
			return skb;
	}

	return NULL;
}


/**
 * insert_skb_in_order - Insert skb into list in sequence order
 * @list: SKB queue to insert into
 * @skb: SKB to insert
 * @seq: Sequence number of skb (host byte order)
 *
 * Inserts @skb into @list, maintaining sequence order (ascending).
 * If an SKB with the same sequence already exists, does not insert.
 *
 * Returns: true if inserted, false if duplicate.
 */
static bool insert_skb_in_order(struct sk_buff_head *list, struct sk_buff *skb,
                                u32 seq)
{
	struct sk_buff *pos;

	pep_dbg("Queuing SKB seq=%u", seq);

	skb_queue_walk(list, pos)
	{
		u32 this_seq = skb_get_seq(pos);

		if (seq < this_seq) {
			__skb_queue_before(list, pos, skb);
			return true;
		} else if (seq == this_seq) {
			/* Duplicate; don't store */
			return false;
		}
	}

	/* if list is empty or seq is largest, insert at tail */
	__skb_queue_tail(list, skb);

	return true;
}


/**
 * mip_rtx_single - Retransmit a single packet
 * @con: Pointer to pepdna connection structure
 * @ack: Latest acknowledged sequence number
 *
 * Retransmits a single packet from mip_rtx_list with sequence numbers >= @seq on the
 * network interface.
 */
static void mip_rtx_single(struct pepcon *con, u32 seq)
{
	struct net_device *dev = dev_get_by_name(&init_net, ifname);
	if (!dev) {
		pep_err("Failed to get net_device for interface: %s", ifname);
		return;
	}

	int hlen = LL_RESERVED_SPACE(dev), tlen = dev->needed_tailroom;
	struct sk_buff *skb;
	bool found = false;

	spin_lock_bh(&con->mip_rtx_list.lock);
	skb_queue_walk(&con->mip_rtx_list, skb)
	{
		struct sk_buff *nskb;
		struct miphdr *hdr;

		if (skb_get_seq(skb) == seq) {
			// Create a NEW copy with proper headroom for rtx
			nskb = skb_copy(skb, GFP_ATOMIC);

			hdr = (struct miphdr *)skb_network_header(nskb);
			hdr->ts = htonl(jiffies_to_msecs(jiffies));

			nskb->dev = dev;
			nskb->protocol = htons(ETH_P_MINIP);
			nskb->no_fcs = 1;
			nskb->pkt_type = PACKET_OUTGOING;

			dev_queue_xmit(nskb);
			found = true;
			break;
		}
	}
	spin_unlock_bh(&con->mip_rtx_list.lock);

	/* Release reference obtained by dev_get_by_name() */
	dev_put(dev);

	if (!found) {
		pep_dbg("Seq %u not found in rtx list", seq);
	}
}


/**
 * mip_rtx_unacked - Retransmit unacknowledged packets
 * @con: Pointer to pepdna connection structure
 * @ack: Latest acknowledged sequence number
 *
 * Retransmits packets from mip_rtx_list with sequence numbers >= @ack on the
 * network interface.
 */
static void mip_rtx_unacked(struct pepcon *con, u32 ack)
{
	struct net_device *dev = dev_get_by_name(&init_net, ifname);
	if (!dev) {
		pep_err("Failed to get net_device for interface: %s", ifname);
		return;
	}

	int hlen = LL_RESERVED_SPACE(dev), tlen = dev->needed_tailroom;
	struct sk_buff *skb;

	spin_lock_bh(&con->mip_rtx_list.lock);
	skb_queue_walk(&con->mip_rtx_list, skb)
	{
		struct sk_buff *nskb;
		struct miphdr *hdr;

		if (skb_get_seq(skb) >= ack) {
			// Create a NEW copy with proper headroom for rtx
			nskb = skb_copy(skb, GFP_ATOMIC);

			hdr = (struct miphdr *)skb_network_header(nskb);
			hdr->ts = htonl(jiffies_to_msecs(jiffies));

			nskb->dev = dev;
			nskb->protocol = htons(ETH_P_MINIP);
			nskb->no_fcs = 1;
			nskb->pkt_type = PACKET_OUTGOING;

			dev_queue_xmit(nskb);
		}
	}
	spin_unlock_bh(&con->mip_rtx_list.lock);

	/* Release reference obtained by dev_get_by_name() */
	dev_put(dev);
}


/* multiply by 1.25  (x + x/4) */
/* static inline u32 cwnd_mul_125(u32 x) { return x + (x >> 1); } */
static inline u32 cwnd_mul_125(u32 x) { return x << 1; }


/* multiply by 0.25   (x/4)     */
static inline u32 cwnd_mul_025(u32 x) { return x >> 2; }


/**
 * mip_ack - Remove acknowledged packets from retransmission queue
 * @con:   Pointer to pepdna connection structure
 * @ack:   Latest acknowledged sequence number
 *
 * Removes and frees all packets from the retransmission queue with
 * sequence numbers less than @ack. Returns the number of packets removed.
 */
static int mip_ack(struct pepcon *con, u32 ack)
{
	struct sk_buff *skb, *tmp;
	int credit = 0;
	u32 seq;

	spin_lock_bh(&con->mip_rtx_list.lock);
	/* Check if there's smth to ack */
	if (skb_queue_empty(&con->mip_rtx_list)) {
		pep_dbg("Empty mip_rtx_list, nothing to ack");
		spin_unlock_bh(&con->mip_rtx_list.lock);
		return 0;
	}

	skb_queue_walk_safe(&con->mip_rtx_list, skb, tmp)
	{
		seq = skb_get_seq(skb);
		if (seq >= ack)
			break;

		pep_dbg("Seq %u acked, mip_rtx_list qlen=%u", seq,
			skb_queue_len(&con->mip_rtx_list));

		__skb_unlink(skb, &con->mip_rtx_list);

		if (skb_unref(skb)) {
			pep_dbg("Freeing skb seq=%u from mip_rtx_list", seq);
			kfree_skb(skb);
		}

		pep_dbg("Deleted seq %u from mip_rtx_list", seq);
		credit++;
		con->pkts_acked++;
		atomic_add_unless(&con->unacked, -1, 0);
	}
	spin_unlock_bh(&con->mip_rtx_list.lock);

	/* Window growth decision – done outside the spinlock */
	if (con->cc_state == CC_ACCEL) {
		u32 cwnd_pkts = atomic_read(&con->cwnd);

		if (con->pkts_acked >= cwnd_pkts) {
			con->pkts_acked -= cwnd_pkts;
			/* cwnd' = cwnd × 1.25  (x + x/4) */
			u32 new_cwnd = cwnd_mul_125(cwnd_pkts);
			/* Optional safety-cap: never exceed max peer's rwnd */
			/* u32 peer_cap = max(1U, con->peer_rwnd / MIP_MSS); */
			/* u32 peer_cap = max(2U, MIP_MAX_CWND_PKTS); */
			/* if (new_cwnd > peer_cap) */
			/* new_cwnd = peer_cap; */
			atomic_set(&con->cwnd, new_cwnd);
			pep_info("CWND growth: %u => %u pkts (ACCEL)", cwnd_pkts,
				 new_cwnd);
		}
	}

	return credit;
}


/**
 * read_more - Notify socket of pending data
 * @con: Pointer to pepdna connection structure
 *
 * Wakes up the underlying socket to handle incoming data for the connection.
 */
static void read_more(struct pepcon *con)
{
	/* Wake up inbound socket in case of pending data */
	con->lsock->sk->sk_data_ready(con->lsock->sk);
}


/* multiplicative decrease: cwnd = max(cwnd/2, 2) */
static inline void cc_brake(struct pepcon *con, const char *reason)
{
        u32 cw = atomic_read(&con->cwnd);
        u32 new_cw = max_t(u32, cwnd_mul_025(cw), 2U);

        if (new_cw != cw) {
                atomic_set(&con->cwnd, new_cw);
                con->pkts_acked = 0;
                con->cc_state   = CC_BRAKE;
                pep_dbg("CWND brake (%s) %u => %u pkts", reason, cw, new_cw);
        }
}


/**
 * update_local_rwnd - Update local receive window size for a PEP connection
 * @con: Pointer to pepdna connection structure
 *
 * Recalculates the local receive window (rwnd) based on the backlog of received
 * packets. If the queue is 75% full or more, sets rwnd to the initial cwnd
 * size. Otherwise, sets rwnd to the available window space or at least one MSS.
 */
static void update_local_rwnd(struct pepcon *con)
{
	/* Define high watermark threshold (75% of WINDOW) */
	const int high_watermark = ((WINDOW_SIZE * 3) >> 2);

	int qlen = skb_queue_len_lockless(&con->mip_rx_list) * MIP_MSS;
	int free = WINDOW_SIZE - qlen;

	/*
	 * If queue is nearly full (>75%), restrict window to minimum.
	 * Otherwise, advertise available space but at least one MSS.
	 */
	if (qlen < high_watermark) {
		con->local_rwnd = (u32)max_t(int, free, (MIP_MSS << 1));
	} else {
		/* advertise half of free space, minimum 2 MSS */
		con->local_rwnd = (u32)max_t(int, (free >> 1), (MIP_MSS << 1));
	}
}


/**
 * pepdna_mip_send_delete - Send a MIP flow delete (FIN) packet
 * @con: Pointer to pepdna connection structure
 *
 * Sends a MIP_CON_DEL (FIN) packet to notify the peer to deallocate the flow.
 */
static void pepdna_mip_send_delete(struct pepcon *con)
{
	struct net_device *dev = dev_get_by_name(&init_net, ifname);
	if (!dev) {
		pr_err("Failed to get net_device for interface: %s", ifname);
		return;
	}

	struct miphdr *hdr;
	int hlen = LL_RESERVED_SPACE(dev);
	int tlen = dev->needed_tailroom;
	int hdr_len = sizeof(struct miphdr);

	/* skb */
	struct sk_buff* skb = alloc_skb(hdr_len + hlen + tlen, GFP_ATOMIC);
	if (!skb) {
		dev_put(dev);
		return;
	}

	skb_reserve(skb, hlen);
	skb_reset_network_header(skb);
	hdr = skb_put(skb, hdr_len);

	/*
	 * Fill out the MIP protocol part
	 */
	hdr->pkt_type = MIP_CON_DEL;
	hdr->sdu_len = 0u;
	hdr->id = htonl(con->id);

	/* Record the very final seq and send it with MIP_CON_DEL */
	WRITE_ONCE(con->final_seq, con->next_seq);
	hdr->seq = htonl(con->next_seq);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_MINIP);
	skb->no_fcs = 1;
	skb->pkt_type = PACKET_OUTGOING;

	/*
	 * Add the link layer
	 */
	if (dev_hard_header(skb, dev, ETH_P_MINIP, con->srv->to_mac,
			    dev->dev_addr, skb->len) < 0)
		goto out;

	pep_dbg("Sending MIP_CON_DEL for conn id %u", con->id);

	dev_queue_xmit(skb);
	dev_put(dev);

	return;
out:
	dev_put(dev);
	kfree_skb(skb);
}

/**
 * minip_zombie_timeout - Cleanup handler for ZOMBIE pepdna connections
 * @t: Pointer to timer_list structure
 *
 * Called when the zombie timer fires. Cleans up RX and RTX lists for a
 * connection in the ZOMBIE state and releases associated references to trigger
 * full cleanup.
 */
void minip_zombie_timeout(struct timer_list *t)
{
	struct pepcon *con = from_timer(con, t, zombie_timer);

	pep_dbg("ZOMBIE TIMER FIRED: conn id %u, state %u", con->id, con->state);

	get_con(con);
	if (con->state == ZOMBIE) {
		pep_dbg("Cleaning up after ZOMBIE conn id %u", con->id);

		/* Purge MIP rx list */
		spin_lock_bh(&con->mip_rx_list.lock);
		__skb_queue_purge(&con->mip_rx_list);
		spin_unlock_bh(&con->mip_rx_list.lock);

		/* Purge MIP rtx list */
		spin_lock_bh(&con->mip_rtx_list.lock);
		__skb_queue_purge(&con->mip_rtx_list);
		spin_unlock_bh(&con->mip_rtx_list.lock);

		// Release the reference held by the timer
		put_con(con);

		// Release reference to trigger full cleanup
		pep_dbg("Calling put_con to trigger full cleanup");
	}

	put_con(con);
}


/**
 * minip_rto_timeout() - Timer that fires in case of pkt. loss or inactivity
 * @t: Pointer to timer_list member of con
 *
 * If fired it means that there was packet loss.
 * Retransmit unacked packets
 * Switch to Slow Start, set the ss_threshold to half of the current cwnd and
 * reset the cwnd to 3*MSS
 */
void minip_rto_timeout(struct timer_list *t)
{
	struct pepcon *con = from_timer(con, t, rto_timer);

	pep_dbg("RTO TIMER FIRED: conn id %u, state %u", con->id, con->state);
	// Critical: Immediately take another reference to prevent premature free
	get_con(con);

	if (con->state == CLOSING) {
		// Use normal RTO for CLOSING state
		pep_dbg("Moving CLOSING conn id %u to ZOMBIE state", con->id);
		WRITE_ONCE(con->state, ZOMBIE);
		mod_timer(&con->zombie_timer,
			  jiffies + msecs_to_jiffies(MIP_ZOMBIE_TIMEOUT));

		goto clean;
	}

	pep_dbg("ACK timeout while mip_rtx_list qlen=%u",
		skb_queue_len_lockless(&con->mip_rtx_list));

	/* resend the non-ACKed packets... if any */
	if (!skb_queue_empty_lockless(&con->mip_rtx_list)) {
		pep_dbg("Rtxing first unacked packet...");

		con->state = RECOVERY;
		/* cc_brake(con, "RTO"); */

		WRITE_ONCE(con->sending, false);
		mip_rtx_single(con, (u32)atomic_read(&con->last_acked) + 1);
		WRITE_ONCE(con->sending, true);

		pep_info("Rtxd pkts [%u, %u] due to RTO (rto=%u ms)",
			 (u32)atomic_read(&con->last_acked) + 1,
			con->next_seq - 1, con->rto);
	} else {
		/* ACK timeout but nothing to rtx, let it expire
		 * TODO: implement inactivity timer
		 */
		goto clean;
	}
clean:
	put_con(con);
}


/**
 * minip_update_rto() - calculate new retransmission timeout
 * @con: pointer to pepdna connection instance
 * @new_rtt: new roundtrip time in msec
 */
static void minip_update_rto(struct pepcon *con, u32 new_rtt)
{
	long m = new_rtt;

	/* RTT update
	 * Details in Section 2.2 and 2.3 of RFC6298
	 *
	 * It's tricky to understand. Don't lose hair please.
	 * Inspired by tcp_rtt_estimator() tcp_input.c
	 */
	if (con->srtt != 0) {
		m -= (con->srtt >> 3); /* m is now error in rtt est */
		con->srtt += m; /* rtt = 7/8 srtt + 1/8 new */
		if (m < 0)
			m = -m;

		m -= (con->rttvar >> 2);
		con->rttvar += m; /* mdev ~= 3/4 rttvar + 1/4 new */
	} else {
		/* first measure getting in */
		con->srtt = m << 3;	/* take the measured time to be srtt */
		con->rttvar = m << 1; /* new_rtt / 2 */
	}

	/* rto = srtt + 4 * rttvar.
	 * rttvar is scaled by 4, therefore doesn't need to be multiplied
	 */
	con->rto = (con->srtt >> 3) + con->rttvar;

	pep_dbg("Updated RTO to %u ms", con->rto);
}


/*
 * Send a MIP_CON_DONE packet, a.k.a FIN/ACK
 * -------------------------------------------------------------------------- */
static int pepdna_mip_send_done(struct pepcon *con)
{
	struct net_device *dev = dev_get_by_name(&init_net, ifname);
	if (!dev) {
		pep_err("Failed to get net_device for interface: %s", ifname);
		return -ENODEV;
	}

	struct miphdr *hdr;
	int hlen = LL_RESERVED_SPACE(dev);
	int tlen = dev->needed_tailroom;
	int hdr_len = sizeof(struct miphdr);

	/* skb */
	struct sk_buff* skb = alloc_skb(hdr_len + hlen + tlen, GFP_ATOMIC);
	if (!skb) {
		dev_put(dev);
		return -ENOMEM;
	}

	skb_reserve(skb, hlen);
	skb_reset_network_header(skb);
	hdr = skb_put(skb, hdr_len);
	/*
	 * Fill out the MINIP protocol part
	 */
	hdr->pkt_type = MIP_CON_DONE;
	hdr->sdu_len = 0u;
	hdr->id = htonl(con->id);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_MINIP);
	skb->no_fcs = 1;
	skb->pkt_type = PACKET_OUTGOING;

	/*
	 * Fill the device header for the MINIP frame
	 */
	if (dev_hard_header(skb, dev, ETH_P_MINIP, con->srv->to_mac,
			    dev->dev_addr, skb->len) < 0)
		goto out;

	dev_queue_xmit(skb);
	dev_put(dev);

	return 0;
out:
	dev_kfree_skb_any(skb);
	dev_put(dev);

	return -1;
}


int pepdna_mip_send_response(struct pepcon *con)
{
	struct miphdr *hdr;
	struct net_device *dev = dev_get_by_name(&init_net, ifname);
	if (!dev) {
		pep_err("Failed to get net_device for interface: %s", ifname);
		return -ENODEV;
	}

	int hlen = LL_RESERVED_SPACE(dev);
	int tlen = dev->needed_tailroom;
	int hdr_len = sizeof(struct miphdr);

	/* skb */
	struct sk_buff* skb = alloc_skb(hdr_len + hlen + tlen, GFP_ATOMIC);
	if (!skb) {
		dev_put(dev);
		return -1;
	}

	skb_reserve(skb, hlen);
	skb_reset_network_header(skb);
	hdr = skb_put(skb, hdr_len);

	/*
	 * Fill out the MINIP protocol part
	 */
	hdr->pkt_type = MIP_CON_RESP;
	hdr->sdu_len = 0u;
	hdr->id = htonl(con->id);
	hdr->seq = htonl(MIP_FIRST_SEQ);
	hdr->ack = htonl(MIP_FIRST_SEQ + 1);
	con->local_rwnd = WINDOW_SIZE;
	hdr->rwnd = htonl(con->local_rwnd);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_MINIP);
	skb->no_fcs = 1;
	skb->pkt_type = PACKET_OUTGOING;

	/*
	 * Fill the device header for the MINIP frame
	 */
	if (dev_hard_header(skb, dev, ETH_P_MINIP, con->srv->to_mac,
			    dev->dev_addr, skb->len) < 0)
		goto out;

	pep_dbg("Sent MIP_CON_RESP [cid %u]", con->id);

	dev_queue_xmit(skb);
	dev_put(dev);

	return 0;
out:
	kfree_skb(skb);
	dev_put(dev);

	return -1;
}


static int pepdna_minip_send_ack(struct pepcon *con, u32 ack, __be32 ts)
{
	struct net_device *dev = dev_get_by_name(&init_net, ifname);
	if (!dev) {
		pep_err("Failed to get net_device for interface: %s", ifname);
		return -ENODEV;
	}

	int hlen = LL_RESERVED_SPACE(dev);
	int tlen = dev->needed_tailroom;
	int hdr_len = sizeof(struct miphdr);
	struct miphdr *hdr;

	/* skb */
	struct sk_buff* skb = alloc_skb(hdr_len + hlen + tlen, GFP_ATOMIC);
	if (!skb) {
		dev_put(dev);
		return -ENOMEM;
	}

	skb_reserve(skb, hlen);
	skb_reset_network_header(skb);
	hdr = skb_put(skb, hdr_len);

	/*
	 * Fill out the MINIP protocol part
	 */
	hdr->pkt_type = MIP_CON_ACK;
	hdr->sdu_len = 0u;
	hdr->id = htonl(con->id);
	hdr->ack = htonl(ack);
	hdr->rwnd = htonl(con->local_rwnd);
	hdr->ts = ts;

	skb->dev = dev;
	skb->protocol = htons(ETH_P_MINIP);
	skb->no_fcs = 1;
	skb->pkt_type = PACKET_OUTGOING;

	/*
	 * Fill the device header for the MINIP frame
	 */
	if (dev_hard_header(skb, dev, ETH_P_MINIP, con->srv->to_mac,
			    dev->dev_addr, skb->len) < 0)
		goto out;

	dev_queue_xmit(skb);
	dev_put(dev);

	return 0;
out:
	kfree_skb(skb);
	dev_put(dev);

	return -1;
}


static int pepdna_mip_send_skb(struct pepcon *con, unsigned char *buf, size_t len)
{
	struct net_device *dev = dev_get_by_name(&init_net, ifname);
	if (!dev) {
		pep_err("Failed to get net_device for interface: %s", ifname);
		return -ENODEV;
	}

	struct sk_buff *cskb = NULL;
	struct miphdr *hdr;
	int hlen = LL_RESERVED_SPACE(dev);
	int tlen = dev->needed_tailroom;
	int hdrlen = sizeof(struct miphdr);

	/* skb */
	struct sk_buff* skb = alloc_skb(len + hdrlen + hlen + tlen, GFP_ATOMIC);
	if (!skb) {
		dev_put(dev);
		return -ENOMEM;
	}

	skb_reserve(skb, hlen);
	skb_reset_network_header(skb);

	/*
	 * Fill out the MIP protocol header
	 */
	hdr = skb_put(skb, hdrlen);
	hdr->pkt_type = MIP_CON_DATA;
	hdr->sdu_len = htons((u16)len);
	hdr->id = htonl(con->id);
	hdr->seq = htonl(con->next_seq);
	hdr->rwnd = htonl(con->local_rwnd);
	hdr->ts = htonl(jiffies_to_msecs(jiffies));

	skb_put_data(skb, buf, len);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_MINIP);
	skb->no_fcs = 1;
	skb->pkt_type = PACKET_OUTGOING;

	/*
	 * Fill the device header for the MIP frame
	 */
	if (dev_hard_header(skb, dev, ETH_P_MINIP, con->srv->to_mac,
			    dev->dev_addr, skb->len) < 0)
		goto out;

	/* Clone skb for the rtx queue */
	/* cskb = skb_clone(skb, GFP_ATOMIC); */
	cskb = skb_copy(skb, GFP_ATOMIC);
	if (!cskb)
		goto out;

	pep_dbg("Transmitting MIP seq %u", con->next_seq);

	/* Copy skb to MIP rtx list */
	spin_lock_bh(&con->mip_rtx_list.lock);
	__skb_queue_tail(&con->mip_rtx_list, cskb);
	/* Increment next seq and unacked counter */
	con->next_seq++;
	atomic_inc(&con->unacked);
	spin_unlock_bh(&con->mip_rtx_list.lock);

	dev_queue_xmit(skb);
	dev_put(dev);

	return 0;
out:
	dev_kfree_skb_any(skb);
	dev_put(dev);

	return -1;
}


/*
 * Send buffer over a MINIP flow
 * ------------------------------------------------------------------------- */
static int pepdna_mip_send_data(struct pepcon *con, unsigned char *buf, size_t len)
{
	size_t left = len, copylen, mss = MIP_MSS;
	size_t sent = 0;
	int rc;

	pep_dbg("Attempting to forward %lu bytes in total to MIP", len);

	while (left) {
		copylen = min_t(size_t, left, mss);

		rc = pepdna_mip_send_skb(con, buf + sent, copylen);
		if (rc < 0) {
			pep_err("Failed to forward skb to MIP");
			rc = -EIO;
			goto out;
		}

		left -= copylen;
		sent += copylen;

		pep_dbg("Forwarded %lu out of %lu bytes to MINIP", sent, len);
	}

	/* Update the timer after sending a window */
	mod_timer(&con->rto_timer, jiffies + msecs_to_jiffies(con->rto));
out:
	return sent ? sent : rc;
}


static int pepdna_mip_send_request(struct pepcon *con)
{
	struct net_device *dev = dev_get_by_name(&init_net, ifname);
	if (!dev) {
		pep_err("Failed to get net_device for interface: %s", ifname);
		return -ENODEV;
	}

	int hlen = LL_RESERVED_SPACE(dev);
	int tlen = dev->needed_tailroom;
	int hdrlen = sizeof(struct miphdr);
	int synlen = sizeof(struct synhdr);
	struct miphdr *hdr;
	struct synhdr *syn;

	/* skb */
	struct sk_buff* skb = alloc_skb(synlen + hdrlen + hlen + tlen, GFP_ATOMIC);
	if (!skb) {
		dev_put(dev);
		return -ENOMEM;
	}

	skb_reserve(skb, hlen);
	skb_reset_network_header(skb);
	hdr = skb_put(skb, hdrlen);
	/*
	 * Fill out the MINIP protocol part
	 */
	hdr->pkt_type = MIP_CON_REQ;
	hdr->sdu_len = htons((u16)synlen);
	hdr->id = htonl(con->id);
	hdr->seq = htonl(MIP_FIRST_SEQ);
	hdr->ack = htonl(MIP_FIRST_SEQ);
	con->local_rwnd = WINDOW_SIZE;
	hdr->rwnd = htonl(con->local_rwnd);
	hdr->ts = htonl(jiffies_to_msecs(jiffies));

	syn = skb_put(skb, synlen);
	syn->saddr = con->syn.saddr;
	syn->source = con->syn.source;
	syn->daddr = con->syn.daddr;
	syn->dest = con->syn.dest;

	/*
	 * Fill the device header for the MINIP frame
	 */
	skb->dev = dev;
	skb->protocol = htons(ETH_P_MINIP);
	skb->no_fcs = 1;
	skb->pkt_type = PACKET_OUTGOING;

	if (dev_hard_header(skb, dev, ETH_P_MINIP, con->srv->to_mac,
			    dev->dev_addr, skb->len) < 0)
		goto out;

	dev_queue_xmit(skb);
	dev_put(dev);

	return 0;
out:
	kfree_skb(skb);
	dev_put(dev);

	return -1;
}


void pepdna_mip_handshake(struct work_struct *work)
{
	struct pepcon *con = container_of(work, struct pepcon, connect_work);

	int rc = pepdna_mip_send_request(con);
	if (rc < 0) {
		pep_err("Failed to send MIP_CON_REQ");

		close_con(con);
		return;
	}

	WRITE_ONCE(con->state, REQ_SENT);
	con->next_seq++; // init value MIP_FIRST_SEQ
}


static int pepdna_mip_recv_done(struct sk_buff *skb)
{
	struct miphdr *hdr = (struct miphdr *)skb_network_header(skb);
	struct pepcon *con;
	u32 hash = ntohl(hdr->id);
	u8 state;

	pep_dbg("Recvd MIP_CON_DONE for conn id %u", hash);

	con = find_con(hash);
	if (!con) {
		pep_err("conn id %u not found", hash);
		return -1;
	}

	state = READ_ONCE(con->state);

	// Handle based on current state
	switch (state) {
	case CLOSING:
		/* We already sent DELETE, and now received DONE */
		pep_dbg("Recvd MIP_CON_DONE: CLOSING => ZOMBIE");
		WRITE_ONCE(con->rflag, false);
		WRITE_ONCE(con->state, ZOMBIE);

		/* Start 30s zombie timer */
		mod_timer(&con->zombie_timer,
			  jiffies + msecs_to_jiffies(MIP_ZOMBIE_TIMEOUT));
		break;
	case ESTABLISHED:
	case RECOVERY:
		/* Received DONE without us sending DELETE first */
		pep_dbg("Recvd unexpected DONE, responding with DELETE");

		/* Send a DELETE packet to acknowledge the DONE */
		pepdna_mip_send_delete(con);

		/* Move directly to ZOMBIE state and close the connection */
		WRITE_ONCE(con->rflag, false);
		WRITE_ONCE(con->state, ZOMBIE);
		mod_timer(&con->zombie_timer,
			  jiffies + msecs_to_jiffies(MIP_ZOMBIE_TIMEOUT));

		/* Close the connection and don't process more pkts */
		close_con(con);
		break;
	case ZOMBIE:
		/* Already in ZOMBIE state, nothing more to do */
		pep_dbg("Recvd DONE while already in ZOMBIE state");
		break;
	default:
		/* For any other state, just mark connection as DONE */
		pep_dbg("Recvd DONE in state %u, closing connection", state);
		WRITE_ONCE(con->rflag, false);
		WRITE_ONCE(con->state, FINISHED);
		close_con(con);
		break;
	}

	/* Throw out 'skb', we're done with it. */
	dev_kfree_skb_any(skb);

	return 0;
}


static int pepdna_mip_recv_delete(struct sk_buff *skb)
{
	struct miphdr *hdr = (struct miphdr *)skb_network_header(skb);
	struct pepcon *con;
	u32 exp_sn, hash = ntohl(hdr->id), final_seq = ntohl(hdr->seq);
	u8 state;

	con = find_con(hash);
	if (!con) {
		pep_err("conn id %u not found", hash);
		return -1;
	}

	/* This is the last seq sender sent + 1 */
	WRITE_ONCE(con->final_seq, final_seq);

	pep_dbg("RECVd MIP_CON_DEL for conn id %u", hash);

	state = READ_ONCE(con->state);
	exp_sn = READ_ONCE(con->next_recv);

	// Handle the DELETE based on current state
	switch (state) {
	case ESTABLISHED:
	case RECOVERY:
		/* Received DELETE in normal operation; peer wants to close
		 * Move to CLOSING and allow queued SKBs to be processed
		 */
		pep_dbg("%s => CLOSING", state == ESTABLISHED ? "ESTABLISHED" : "RECOVERY");

		/* WRITE_ONCE(con->rflag, false); */
		if (exp_sn < final_seq)
			WRITE_ONCE(con->dont_close, true);

		WRITE_ONCE(con->state, CLOSING);
		mod_timer(&con->rto_timer,
			  jiffies + msecs_to_jiffies(con->rto));
		/* Don't close the inbound TCP socket yet */
		/* close_con(con); */

		/* Schedule work to drain the MINIP rx queue and close */
		get_con(con);
		if (!queue_work(con->srv->out2in_wq, &con->out2in_work)) {
			pep_dbg("out2in work already on a queue");
			put_con(con);
		}
		break;
	case CLOSING:
		pep_dbg("CLOSING => ZOMBIE");

		// Always send FINISHED in CLOSING state
		if (pepdna_mip_send_done(con) < 0)
			pep_err("Failed to send MIP_CON_DONE");
		else
			pep_dbg("Sent MIP_CON_DONE [cid %u]", hash);

		WRITE_ONCE(con->rflag, false);
		WRITE_ONCE(con->state, ZOMBIE);
		close_con(con);
		mod_timer(&con->zombie_timer,
			  jiffies + msecs_to_jiffies(MIP_ZOMBIE_TIMEOUT));
		break;
	case ZOMBIE:
		// Already in ZOMBIE state, just acknowledge it
		pep_dbg("Received DELETE while already in ZOMBIE state");
		break;
	default:
		// For any other state, transition to FINISHED
		pep_dbg("Received DELETE in state %u: => FINISHED", state);
		WRITE_ONCE(con->rflag, false);
		WRITE_ONCE(con->state, FINISHED);
		close_con(con);
		break;
	}

	/* Throw out 'skb', we're done with it. */
	dev_kfree_skb_any(skb);

	return 0;
}


static int pepdna_mip_recv_ack(struct sk_buff *skb)
{
	struct miphdr *hdr = (struct miphdr *)skb_network_header(skb);
	struct pepcon *con = NULL;
	u32 ack, last_acked, rwnd, hash;
	int credit;
	u8 state;

	/* Parse header */
	hash = ntohl(hdr->id);
	rwnd = ntohl(hdr->rwnd);
	ack = (u32)(ntohl(hdr->ack));

	/* Find connection */
	con = find_con(hash);
	if (!con) {
		pep_err("conn id %u not found", hash);
		return -ENOENT;
	}

	/* Check connection state */
	state = READ_ONCE(con->state);
	if (state == FINISHED) {
		pep_err("conn id %d already finished", hash);
		/* Do NOT free 'skb' here, caller will take care. */
		return -1;
	}

	last_acked = (u32)atomic_read(&con->last_acked);

	pep_dbg("RECV_ACK %u: cid=%u, last_acked=%u, peer_rwnd=%u", ack, hash,
		last_acked, rwnd);

	/* old ACK? silently drop it..update the rwnd..and wake up socket */
	if (unlikely(ack <= last_acked)) {
		pep_dbg("Dropping old ACK %u", ack);
		con->peer_rwnd = rwnd;
		mod_timer(&con->rto_timer,
			  jiffies + msecs_to_jiffies(con->rto));
		WRITE_ONCE(con->sending, true);
		read_more(con);
		goto drop;
	}

	/* Check if this is a dup ACK or the very last ACK */
	if (ack == (u32)atomic_read(&con->dupACK)) {
		/* Do not process dupACKs in ZOMBIE state */
		if (state == ZOMBIE)
			goto drop;

		/* If this is the last ACK the sender won't send more SKBs */
		if (ack == READ_ONCE(con->final_seq)){
			/* Send a MIP_CON_DEL to speedup the conn termination */
			pepdna_mip_send_delete(con);

			/* Move directly to ZOMBIE state */
			WRITE_ONCE(con->rflag, false);
			WRITE_ONCE(con->state, ZOMBIE);
			mod_timer(&con->zombie_timer,
				  jiffies + msecs_to_jiffies(MIP_ZOMBIE_TIMEOUT));

			goto drop;
		}

		/* Duplicate ACK */
		pep_dbg("Duplicate ACK %u received", ack);

		if (atomic_inc_return(&con->dup_acks) != 3) {
			pep_dbg("Dropping useless dupACKs");
			goto drop;
		}

		pep_dbg("Third dupACK detected, entering RECOVERY if unacked");

		if (!skb_queue_empty_lockless(&con->mip_rtx_list)) {
			if (READ_ONCE(con->state) != CLOSING)
				WRITE_ONCE(con->state, RECOVERY);

			cc_brake(con, "3-dupACK");

			WRITE_ONCE(con->sending, false);
			mip_rtx_single(con, ack);
			WRITE_ONCE(con->sending, true);

			pep_info("Rtxd seq=%u in RECOVERY after 3rd dupACK", ack);
		}

		/* Reset time after Single RTX */
		mod_timer(&con->rto_timer, jiffies + msecs_to_jiffies(con->rto));

		/* Do not process dup ACKs */
		goto drop;
	}

	pep_dbg("New ACK %u arrived (previous last_acked %u)", ack, last_acked);

	/* ACK arrived... reset the timer if not in ZOMBIE state */
	if (state != ZOMBIE)
		mod_timer(&con->rto_timer, jiffies + msecs_to_jiffies(con->rto));

	/* update RTO with the new sampled RTT, since this is a good ACK */
	u32 ts = ntohl(hdr->ts);
	u32 now = jiffies_to_msecs(jiffies);

	if (ts && now > ts) {
		u32 rtt = now - ts;
		minip_update_rto(con, rtt);
	}

	/* Update dupACK tracking for new value */
	atomic_set(&con->dupACK, ack);
	/* reset the duplicate ACKs counter */
	atomic_set(&con->dup_acks, 0);

	/* Update LWE */
	atomic_set(&con->last_acked, ack - 1);
	/* Remove acked pkts from rtxq (updates con->unacked also) */
	credit = mip_ack(con, ack);

	con->peer_rwnd = rwnd;
	pep_dbg("Updated peer_rwnd to %u", rwnd);

	/* Process ACKs similarly in both CLOSING and ZOMBIE states */
	state = READ_ONCE(con->state);
	if (state != CLOSING && state != ZOMBIE) {
		/* Resume sending new data only if in normal states */
		WRITE_ONCE(con->sending, true);
		/* case: RECOVERY => ESTABLISHED */
		WRITE_ONCE(con->state, ESTABLISHED);
		/* Read more */
		read_more(con);
	}
drop:
	/* Throw out 'skb', we're done with it. */
	dev_kfree_skb_any(skb);

	return 0;
}


static int pepdna_mip_recv_data(struct sk_buff *skb)
{
	struct miphdr *hdr = (struct miphdr *)skb_network_header(skb);
	u32 hash = ntohl(hdr->id), seq = ntohl(hdr->seq), exp_seq;
	u8 state;
	bool need_sched = false;
	bool must_send_ack = false;

	struct pepcon *con = find_con(hash);
	if (!con) {
		pep_err("conn id %u not found", hash);
		return -ENOENT;
	}

	state = READ_ONCE(con->state);
	exp_seq = READ_ONCE(con->next_recv);

	pep_dbg("RECV MIP seq %u (exp seq=%u), conn id %u, mip_rx_len=%u", seq,
		exp_seq, hash, skb_queue_len_lockless(&con->mip_rx_list));

	/* Accept new packets only in ESTABLISHED, RECOVERY, and CLOSING (just
	 * in case DELETE comes sooner than last packets) states
	 */
	if (state == FINISHED || state == ZOMBIE) {
		pep_dbg("Dropping skb, conn id %u state not valid", hash);

		/* Don't send an ACK, let the sender timer expire */
		return -1;
	}

	/* Drop old SKBs and send up to 3 dupACKs (no rwnd update) */
	if (seq < exp_seq) {
		pep_dbg("Old seq %u received", seq);

		if (con->out_of_order_pkt_cnt++ < 3) {
			/* Send a dupACK */
			pepdna_minip_send_ack(con, exp_seq, hdr->ts);
			pep_dbg("Sent dupACK %u, rwnd=%u due to old seq=%u",
				exp_seq, con->local_rwnd, seq);
		}

		return -1;
	}

	/* SKB is in order => reset the out of order counter; enqueue the SKB
	 * and update con->next_recv while holding the spinlock.
	 */

	pep_dbg("Processing new SKB seq=%u (expected=%u)", seq, exp_seq);

	spin_lock_bh(&con->mip_rx_list.lock);
	/* First check if we already have this sequence */
	if (find_skb_by_seq(&con->mip_rx_list, seq)) {
		spin_unlock_bh(&con->mip_rx_list.lock);
		pep_dbg("Duplicate seq %u, sending ACK %u", seq, exp_seq);
		pepdna_minip_send_ack(con, READ_ONCE(con->next_recv), hdr->ts);

		return -1;
	}

	/* Insert the SKB in sequence order */
	if (unlikely(!insert_skb_in_order(&con->mip_rx_list, skb, seq))) {
		/* This should not happen as we checked for duplicate */
		spin_unlock_bh(&con->mip_rx_list.lock);
		pep_dbg("Failed to insert seq %u in order", seq);
		pepdna_minip_send_ack(con, READ_ONCE(con->next_recv), hdr->ts);

		return -1;
	}

	/* If this was the expected sequence, we might need to schedule work */
	u32 next_seq;
	if (seq == exp_seq) {
		struct sk_buff *pos;
		next_seq = exp_seq;

		con->out_of_order_pkt_cnt = 0;
		need_sched = true;

		/* Walk the list to find highest contiguous sequence */
		skb_queue_walk(&con->mip_rx_list, pos)
		{
			u32 this_seq = skb_get_seq(pos);

			if (this_seq == next_seq)
				next_seq++;
			else if (this_seq > next_seq)
				break;  /* Gap found */
		}

		WRITE_ONCE(con->next_recv, next_seq);
		/* if (next_seq - seq > 3) */
		/* 	must_send_ack = true; */

		pep_dbg("Recvd exp_seq %u, contiguous up to %u", seq, next_seq - 1);
	}
	spin_unlock_bh(&con->mip_rx_list.lock);

	/* Update local rcv window */
	update_local_rwnd(con);

	/* ack handling */
	u8 ack_count = ++con->ack_pending;
	//EXPERIMENTAL
	/* if (ack_count < 3 || ack_count % 3 == 0 || must_send_ack) { */
	if (ack_count < 4 || ack_count % 8 == 0) {
		/* Send an ACK with the expected sequence */
		pepdna_minip_send_ack(con, READ_ONCE(con->next_recv), hdr->ts);
		/* must_send_ack = false; */

		pep_dbg("Sent ACK %u (rwnd %u bytes)", con->next_recv, con->local_rwnd);

		if (ack_count == 255)
			con->ack_pending = 2;
	}

	/* Close if the sender already sent everything */
	if (READ_ONCE(con->next_recv) == READ_ONCE(con->final_seq))
		WRITE_ONCE(con->dont_close, false);

	/* Finally, schedule work if needed to drain the mip_rx_list */
	if (need_sched) {
		get_con(con);
		if (!queue_work(con->srv->out2in_wq, &con->out2in_work)) {
			pep_dbg("Failed to queue out2in work");
			put_con(con);
		}
	}

	return 0;
}


static int pepdna_mip_recv_response(struct sk_buff *skb)
{
	struct miphdr *hdr = (struct miphdr *)skb_network_header(skb);
	struct pepcon *con = NULL;
	u32 hash = ntohl(hdr->id);

	pep_dbg("Recvd MIP_CON_RESP for conn id %u", hash);

	con = find_con(hash);
	if (!con) {
		pep_err("conn id %u not found", hash);
		return -ENOENT;
	}

	WRITE_ONCE(con->rflag, true);
	/* atomic_inc(&con->last_acked); */
	atomic_set(&con->last_acked, MIP_FIRST_SEQ);
	WRITE_ONCE(con->state, ESTABLISHED);
	con->next_recv++;

	/* Update peer rwnd */
	con->peer_rwnd = ntohl(hdr->rwnd);

	/* At this point, MINIP flow is allocated. Reinject SYN in back
	 * in the stack so that the left TCP connection can be
	 * established. There is no need to set callbacks here for the
	 * left socket as pepdna_tcp_accept() will take care of it.
	 */
	pep_dbg("Reinjecting initial SYN back to stack");
#ifndef CONFIG_PEPDNA_LOCAL_SENDER
	netif_receive_skb(con->skb);
#else
	ip_local_out(sock_net(con->srv->listener->sk),
		     con->srv->listener->sk,
		     con->skb);
#endif
	/* skb ownership was transferred to the stack; clear reference now */
	con->skb = NULL;
	/* Throw out 'skb', we're done with it. */
	dev_kfree_skb_any(skb);

	return 0;
}


static int pepdna_mip_recv_request(struct sk_buff *skb)
{
	struct miphdr *hdr = (struct miphdr *)skb_network_header(skb);
	struct pepcon *con;
	struct synhdr *syn;
	u32 hash;

	skb_pull(skb, sizeof(struct miphdr));
	syn = (struct synhdr *)skb->data;
	hash = pepdna_hash32_rjenkins1_2(syn->saddr, syn->source);

	pep_dbg("Recvd MIP_CON_REQ for conn id %u", hash);

	con = init_con(syn, NULL, hash, 0ull, 0);
	if (!con) {
		pep_err("Failed to init pepdna connection");
		/* Do NOT free 'skb' in this case.
		   pepdna_minip_skb_recv() will take care of it since
		   we return -ENOMEM. */
		return -ENOMEM;
	}

	/* set state to REQ_RECVD */
	WRITE_ONCE(con->state, REQ_RECVD);
	/* Update the peer rwnd */
	con->peer_rwnd = ntohl(hdr->rwnd);

	/* Throw out 'skb', we're done with it. */
	dev_kfree_skb_any(skb);

	return 0;
}


/* Create static array of handlers */
static pkt_handler_t pkt_handlers[] = {
	[MIP_CON_REQ]  = pepdna_mip_recv_request,
	[MIP_CON_RESP] = pepdna_mip_recv_response,
	[MIP_CON_DATA] = pepdna_mip_recv_data,
	[MIP_CON_ACK]  = pepdna_mip_recv_ack,
	[MIP_CON_DEL]  = pepdna_mip_recv_delete,
	[MIP_CON_DONE] = pepdna_mip_recv_done,
};


/**
 * pepdna_mip_recv_packet - Process incoming MIP packets
 * @skb: Socket buffer containing MIP packet
 *
 * Determines the packet type and dispatches to the appropriate handler
 * Returns: The return value from the specific handler
 */
int pepdna_mip_recv_packet(struct sk_buff *skb)
{
	/* Ensure network header always points right after Ethernet header */
	/* skb_set_network_header(skb, ETH_HLEN); */

	/* Get MIP header pointer */
	struct miphdr *hdr = (struct miphdr *)skb_network_header(skb);

	/* Get packet type using the fast accessor with prefetch */
	u8 pkt_type = get_pkt_type_prefetch(hdr);

	/* Bounds check and dispatch */
	if (likely(pkt_type > 0 &&
		   pkt_type < ARRAY_SIZE(pkt_handlers) &&
		   pkt_handlers[pkt_type])) {
		return pkt_handlers[pkt_type](skb);
	}

	/* Handle unknown packet types */
	pep_dbg("Unknown MIP packet type: %d", pkt_type);
	print_hex_dump_bytes("pepdna-mip",
			     DUMP_PREFIX_NONE, hdr, 23);
	return -EINVAL;
}


/**
 * can_forward - Determine how much bytes can we forward from TCP to MIP
 * @con: Pointer to the connection structure
 *
 * Returns the number of bytes that the sender is allowed to forward.
 */
static int can_forward(struct pepcon *con, struct socket *sock)
{
	int unacked, cwnd = (int)atomic_read(&con->cwnd);
	int rwnd = con->peer_rwnd, mss = MIP_MSS;

	if (!READ_ONCE(con->sending)) {
		/* If we can't send anything, check for EOF in case the sender
		 * has closed the socket. This should not be expensive as we are
		 * not allowed to send anyways.
		 */
		pep_dbg("Sending is disabled, checking for EOF/FIN...");

		char peek_buf[1]; /* PEEK just one byte */
		struct msghdr msg = {
			.msg_flags = MSG_DONTWAIT | MSG_PEEK,
		};
		struct kvec vec = {
			.iov_base = peek_buf,
			.iov_len = 1,
		};

		/* Perform a zero-byte read to detect connection closure */
		if (!kernel_recvmsg(sock, &msg, &vec, 1, 1, msg.msg_flags)) {
			pep_dbg("EOF detected: connection shutting down");
			return -ESHUTDOWN;
		}

		return 0;
	}

	unacked = atomic_read(&con->unacked) * MIP_MSS;
	cwnd *= MIP_MSS;

	/* Don't send more than the cwnd allows */
	if (unacked >= cwnd)
		return 0;

	/* Calculate the effective receiving window */
	int erwnd = rwnd - unacked;

	pep_dbg("CAN_FORWARD: sending=%d, unacked=%d, peer_rwnd=%u, erwnd=%d, cwnd=%d",
		READ_ONCE(con->sending), unacked, con->peer_rwnd, erwnd, cwnd);

	/* If there is available window, allow sending up to erwnd bytes.
	 * If the window is closed (erwnd <= 0), allow sending one probe
	 * segment if less than 87.5% of the configured window is in flight.
	 */
	/* if (erwnd > 0) { */
	/* 	return erwnd; */
	/* } else if (unacked < ((WINDOW_SIZE * 7) >> 3)) { */
	/* 	return MIP_MSS; */
	/* } */

	if (erwnd > 0) {
		con->cc_state = CC_ACCEL;
		return min_t(int, rwnd, cwnd);
	}

	/* receiver is full (≤0 bytes free) - brake */
	if (con->cc_state == CC_ACCEL)
		cc_brake(con, "rwnd-full");

	return 0;
}

/**
 * pepdna_tcp2mip_fwd - Forward data from TCP socket to MINIP flow
 * @con: Pointer to the connection structure
 * @from: Pointer to the TCP socket to read from
 *
 * Reads data from the TCP socket and forwards it to the MINIP flow.
 * Returns the number of bytes forwarded, or -EAGAIN if no data can be sent.
 */
static int pepdna_tcp2mip_fwd(struct pepcon *con, struct socket *from)
{
	int rx, tx, total_rx = 0, cwnd = can_forward(con, from);

	if (!cwnd) {
		pep_dbg("Cannot forward from TCP to MINIP, try -EAGAIN later");
		return -EAGAIN;
	} else if (cwnd < 0) {
		pep_dbg("conn id %u is shutting down...", con->id);
		return -1;
	}

	pep_dbg("About to read cwnd %d bytes from TCP sock to MIP", cwnd);

	while (cwnd > 0) {
		size_t to_read = min_t(size_t, cwnd, 4431);

		struct kvec vec = {
			.iov_base = con->rx_buff,
			.iov_len = to_read,
		};
		struct msghdr msg = {
			.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL,
		};

		rx = kernel_recvmsg(from, &msg, &vec, 1, to_read, MSG_DONTWAIT);
		pep_dbg("Read %d bytes from TCP sock to be sent to MINIP", rx);
		if (rx > 0) {
			tx = pepdna_mip_send_data(con, con->rx_buff, rx);
			if (tx < 0) {
				pep_err("Failed to forward to MINIP flow");
				return -1;
			}

			total_rx += rx;
			cwnd -= rx;

			if ((size_t)rx < to_read)
				break;
		} else {
			return rx;
		}
	}

	return total_rx;
}

/**
 * pepdna_tcp2mip_work - Forward data from TCP to MINIP flow
 * @work: work structure embedded in pepcon
 *
 * This function is called from the workqueue to forward data from the TCP
 * socket to the MINIP flow. It reads data from the TCP socket and sends it
 * over the MINIP connection.
 *
 * Context: Executed in process context within a kernel worker thread (kworker)
 */
void pepdna_tcp2mip_work(struct work_struct *work)
{
	struct pepcon *con = container_of(work, struct pepcon, in2out_work);
	int rc;

	while (lconnected(con)) {
		if ((rc = pepdna_tcp2mip_fwd(con, con->lsock)) <= 0) {
			if (rc == -EAGAIN)
				break;
			/* Send a MIP_CON_DEL to deallocate the flow */
			pep_dbg("Sending MIP_CON_DEL => move to CLOSING state");
			pepdna_mip_send_delete(con);

			/* Move to CLOSING state and do not send new data.
			 * Meanwhile, wait for MIP_CON_DEL and process
			 * incoming MINIP pkts */
			/* WRITE_ONCE(con->rflag, false); */
			WRITE_ONCE(con->state, CLOSING);
			mod_timer(&con->rto_timer,
				  jiffies + msecs_to_jiffies(con->rto));

			close_con(con);
		}
	}
	/* this work is launched with get_con() */
	put_con(con);
}

/*
 * Forward data from MINIP flow to TCP socket
 * ------------------------------------------------------------------------- */
static int pepdna_mip2tcp_fwd(struct pepcon *con, struct sk_buff *skb)
{
	struct miphdr *hdr = (struct miphdr *)skb_network_header(skb);
	unsigned char *buff;
	int rx, tx;
	u32 seq, last_seq;

	skb_pull(skb, sizeof(struct miphdr));
	buff = (unsigned char *)skb->data;
	rx = ntohs(hdr->sdu_len);

	pep_dbg("Forwarding MIP seq %u of %d bytes to TCP", ntohl(hdr->seq), rx);

	tx = pepdna_sock_write(con->lsock, buff, rx);

	pep_dbg("Forwarded %d / %d bytes from MIP to TCP", tx, rx);

	if (READ_ONCE(con->state) == CLOSING) {
		seq = ntohl(hdr->seq);
		last_seq = READ_ONCE(con->final_seq);
		if (seq == last_seq - 1) {
			/* Send a DELETE packet to acknowledge the DONE */
			pepdna_mip_send_delete(con);

			/* Move directly to ZOMBIE state and close the connection */
			WRITE_ONCE(con->rflag, false);
			WRITE_ONCE(con->state, ZOMBIE);
			mod_timer(&con->zombie_timer,
				  jiffies + msecs_to_jiffies(MIP_ZOMBIE_TIMEOUT));

			close_con(con);
		}
	}
	return tx;
}


/**
 * pepdna_mip2tcp_work - Forward contiguous MIP packets to TCP
 * @work: work structure embedded in pepcon
 *
 * Processes contiguous packets from MIP receive queue and forwards to TCP.
 * Updates receive window and handles connection closing if needed.
 * Called from pepdna_mip_recv_data() via queue_work().
 *
 * Context: Executed in process context within a kernel worker thread (kworker)
 */
void pepdna_mip2tcp_work(struct work_struct *work)
{
	struct pepcon *con = container_of(work, struct pepcon, out2in_work);
	struct sk_buff *skb;
	struct sk_buff_head tmp;
	u16 rc;

	if (unlikely(!rconnected(con)))
		goto release;

	/* tmp doesn't need a spinlock since this work cannot run concurrently*/
	__skb_queue_head_init(&tmp);
	u32 next_recv = READ_ONCE(con->next_recv);

	/* Move only contiguous packets to tmp list */
	pep_dbg("Forwarding SKBs up to seq=%u to TCP", next_recv - 1);

	spin_lock_bh(&con->mip_rx_list.lock);
	while ((skb = skb_peek(&con->mip_rx_list))) {
		u32 seq = skb_get_seq(skb);

		/* Stop if we hit a gap or reached next_recv */
		if (seq > next_recv)
			break;

		/* Remove from main list and add to tmp */
		__skb_unlink(skb, &con->mip_rx_list);
		__skb_queue_tail(&tmp, skb);
		rc++;
	}
	spin_unlock_bh(&con->mip_rx_list.lock);

	/* This may happen when MIP_CON_DEL arrived */
	if (rc == 0) {
		/* CLOSING state and empty queue => check con->dont_close */
		pep_dbg("con->state = CLOSING and empty mip_rx_list");
		if (READ_ONCE(con->state) == CLOSING &&
		    !READ_ONCE(con->dont_close)) {
			/* Send a MIP_CON_DEL to deallocate the flow */
			pepdna_mip_send_delete(con);

			/* Just close the connection and wait... */
			mod_timer(&con->rto_timer,
				  jiffies + msecs_to_jiffies(con->rto));
			close_con(con);
		}
		goto release;
	}

	/* Update local rwnd */
	update_local_rwnd(con);

	/* Send ACK with init seq and tstamp 0 to notify the new rwnd ONLY if
	 * the skb batch is > MIP_INIT_CWND x 0.5
	 */
	if (rc > (MIP_INIT_CWND >> 1)) {
		pepdna_minip_send_ack(con, MIP_FIRST_SEQ, 0);
	}

	/* Finally, start draining the tmp queue and forward to TCP socket */
	while ((skb = __skb_dequeue(&tmp))) {
		if (pepdna_mip2tcp_fwd(con, skb) < 0) {
			/* Send a MIP_CON_DEL to deallocate the flow */
			pepdna_mip_send_delete(con);

			/* Switch to CLOSING state and wait... */
			/* WRITE_ONCE(con->rflag, false); */
			WRITE_ONCE(con->state, CLOSING);
			mod_timer(&con->rto_timer,
				  jiffies + msecs_to_jiffies(con->rto));
			close_con(con);
			break;
		}
	}
release:
	// Release the work reference
	put_con(con);
}
