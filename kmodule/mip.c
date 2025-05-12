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
/* Send window size (100 * MIP_MSS). */
#define WINDOW_SIZE ((65535 / MIP_MSS) * MIP_MSS)


/**
 * skb_get_seq - Retrieve sequence number from skb
 * @skb: pointer to skb
 *
 * Returns the u32 sequence number from the miphdr in host order.
 */
static u32 skb_get_seq(struct sk_buff *skb)
{
	struct miphdr *hdr = (struct miphdr *)skb_network_header(skb);

	return ntohl(hdr->seq);
}


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

			dev_hard_header(nskb, dev, ETH_P_MINIP,
					con->srv->to_mac, dev->dev_addr,
					nskb->len);

			dev_queue_xmit(nskb);
		}
	}
	spin_unlock_bh(&con->mip_rtx_list.lock);

	dev_put(dev);
}


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
		atomic_add_unless(&con->unacked, -1, 0);
	}
	spin_unlock_bh(&con->mip_rtx_list.lock);

	return credit;
}


static void update_cwnd(struct pepcon *con, int credit)
{
	u16 new_cwnd, unacked = (u16)atomic_read(&con->unacked);

	/* Step 1: Increase with 'credit' after a good ACK */
	new_cwnd = con->cwnd + credit;

	/* Step 2: Limit cwnd to receiver's advertised rwnd */
	new_cwnd = min_t(u16, new_cwnd, (con->peer_rwnd / MIP_MSS));

	/* Step 3: Ensure cwnd is at least 10 MSS */
	/* new_cwnd = max_t(u16, new_cwnd, MIP_INIT_CWND); */
	new_cwnd = max_t(u16, new_cwnd, 2);

	/* Step 4: Apply the updated cwnd */
	con->cwnd = new_cwnd + 1;

	/* WRITE_ONCE(con->sending, (unacked < new_cwnd)); */

	/* Step 5: Wake up inbound socket in case of pending data */
	con->lsock->sk->sk_data_ready(con->lsock->sk);

	pep_dbg("UPDATE_CWND: cwnd=%u, rwnd=%u, unacked=%u", con->cwnd,
		con->peer_rwnd, unacked);
}


static void update_local_rwnd(struct pepcon *con)
{
	/* Update local rwnd (in bytes) */
	int qlen = skb_queue_len_lockless(&con->mip_rx_list) * MIP_MSS;
	int free = (int)WINDOW_SIZE - qlen;

	con->local_rwnd = (free >= MIP_MSS) ? free : MIP_MSS;

	/* Check if the SKB list is building up (>= 75%) */
	/* if (qlen >= ((WINDOW_SIZE * 3) >> 2)) { */
	/* 	con->local_rwnd = MIP_MSS << 3; // 8*MSS */
	/* } else { */
	/* 	con->local_rwnd = (free >= MIP_MSS) ? free : MIP_MSS; */
	/* } */
}


/*
 * Send a MIP_CON_DEL packet, a.k.a FIN, to deallocate the MINIP flow
 * -------------------------------------------------------------------------- */
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
 * minip_rto_timeout() - timer that fires in case of pkt. loss or inactivity
 * @t: address to timer_list inside con
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
		pep_dbg("Rtxing unacked pkts...");
		WRITE_ONCE(con->sending, false);
		/* Retransmit all pkts in the mip_rtx_list */
		con->state = RECOVERY;
		mip_rtx_unacked(con, (u32)atomic_read(&con->last_acked) + 1);

		pep_dbg("Rtxd pkts [%u, %u] due to RTO (rto=%u ms)",
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


/* minip_update_rto() - calculate new retransmission timeout
 * @con: connection instance
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

	/* Copy skb to MIP rtx list */
	spin_lock_bh(&con->mip_rtx_list.lock);
	__skb_queue_tail(&con->mip_rtx_list, cskb);
	/* Increment next seq and unacked counter */
	con->next_seq++;
	atomic_inc(&con->unacked);
	spin_unlock_bh(&con->mip_rtx_list.lock);

	pep_dbg("Transmitted skb seq %u", con->next_seq);

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
		copylen = min(left, mss);

		rc = pepdna_mip_send_skb(con, buf + sent, copylen);
		if (rc < 0) {
			pep_err("Failed to forward SKB to MIP");
			rc = -EIO;
			goto out;
		}

		left -= copylen;
		sent += copylen;

		pep_dbg("Forwarded %lu out of %lu bytes to MINIP", sent, len);

		/* Update the timer after sending a new skb */
		mod_timer(&con->rto_timer, jiffies + msecs_to_jiffies(con->rto));
	}
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
	u32 hash = ntohl(hdr->id);
	u8 state;

	con = find_con(hash);
	if (!con) {
		pep_err("conn id %u not found", hash);
		return -1;
	}

	pep_dbg("Recvd MIP_CON_DEL for conn id %u", hash);

	state = READ_ONCE(con->state);

	// Handle the DELETE based on current state
	switch (state) {
	case ESTABLISHED:
	case RECOVERY:
		/* Received DELETE in normal operation; peer wants to close
		 * Move to CLOSING and allow queued SKBs to be processed
		 */
		pep_dbg("%s => CLOSING", state == ESTABLISHED ? "ESTABLISHED" : "RECOVERY");

		/* WRITE_ONCE(con->rflag, false); */
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
	u32 ack, last_acked, rwnd, hash, rtt;
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

	/* Check state */
	state = READ_ONCE(con->state);
	if (state == FINISHED) {
		pep_err("conn id %d already finished", hash);
		/* Do NOT free 'skb' here, caller will take care. */
		return -1;
	}

	last_acked = (u32)atomic_read(&con->last_acked);

	pep_dbg("RECV_ACK %u: cid=%u, last_acked=%u, peer_rwnd=%u, cwnd=%u",
		ack, hash, last_acked, rwnd, con->cwnd);

	/* old ACK? silently drop it..update the rwnd..and wake up socket */
	if (unlikely(ack <= last_acked)) {
		pep_dbg("Dropping old ACK %u", ack);
		con->peer_rwnd = rwnd;
		mod_timer(&con->rto_timer,
			  jiffies + msecs_to_jiffies(con->rto));
		WRITE_ONCE(con->sending, true);
		update_cwnd(con, 2);
		goto drop;
	}

	/* Check if this is a dup ACK */
	if (ack == (u32)atomic_read(&con->dupACK)) {
		/* Do not process dup ACKs in CLOSING or ZOMBIE state */
		if (state == CLOSING || state == ZOMBIE)
			goto drop;
		atomic_inc(&con->dup_acks);

		pep_dbg("Duplicate ACK %u received", ack);

		if (atomic_read(&con->dup_acks) != 1) {
			pep_dbg("Dropping extra DupACKs");
			goto drop;
		}

		pep_dbg("First dup ACK detected, entering RECOVERY if unacked");

		if (!skb_queue_empty_lockless(&con->mip_rtx_list)) {
			WRITE_ONCE(con->state, RECOVERY);
			WRITE_ONCE(con->sending, false);

			/* if this is the first dup ACK, Full Retransmit */
			mip_rtx_unacked(con, ack);
		}

		/* Reset time after Full Rtx */
		mod_timer(&con->rto_timer, jiffies + msecs_to_jiffies(con->rto));

		/* Do not process dup ACKs */
		goto drop;
	}

	pep_dbg("New ACK %u received (previous last_acked %u)", ack, last_acked);

	/* ACK arrived... reset the timer if not in ZOMBIE state */
	if (state != ZOMBIE)
		mod_timer(&con->rto_timer, jiffies + msecs_to_jiffies(con->rto));

	/* update RTO with the new sampled RTT, since this is a good ACK */
	rtt = jiffies_to_msecs(jiffies) - ntohl(hdr->ts);
	if (hdr->ts && rtt)
		minip_update_rto(con, rtt);

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
	if (state != CLOSING && state != ZOMBIE) {
		/* Resume sending new data only if in normal states */
		WRITE_ONCE(con->sending, true);
		/* case: RECOVERY => ESTABLISHED */
		WRITE_ONCE(con->state, ESTABLISHED);
		/* Update cwnd */
		update_cwnd(con, credit);
	}
drop:
	/* Throw out 'skb', we're done with it. */
	dev_kfree_skb_any(skb);

	return 0;
}


static int pepdna_mip_recv_data(struct sk_buff *skb)
{
	struct miphdr *hdr = (struct miphdr *)skb_network_header(skb);
	struct pepcon *con = NULL;
	u32 hash = ntohl(hdr->id), seq = ntohl(hdr->seq), exp_sn;
	u8 state;

	con = find_con(hash);
	if (!con) {
		pep_err("conn id %u not found", hash);
		return -ENOENT;
	}

	state = READ_ONCE(con->state);
	exp_sn = READ_ONCE(con->next_recv);

	pep_dbg("RECV MIP seq %u (exp seq=%u), conn id %u, mip_rx_len=%u", seq,
		exp_sn, hash, skb_queue_len_lockless(&con->mip_rx_list));

	/* Accept new packets only in ESTABLISHED, RECOVERY, and CLOSING (just
         * in case DELETE comes sooner than last packets) states
	 */
	if (state == FINISHED || state == ZOMBIE) {
		pep_dbg("Dropping skb, conn id %u state not valid", hash);

		/* Don't send an ACK, let the sender timer expire */
		return -1;
	}

	/* Do not enqueue old SKBs => no local_rwnd change */
	if (seq != exp_sn) {
		/* Send an ACK to prevent sender retransmissions */
		pepdna_minip_send_ack(con, exp_sn, hdr->ts);
		pep_info("seq %u not in order, sent cleanup ACK %u lo_rwnd=%u",
			 seq, exp_sn, con->local_rwnd);

		/* Schedule work to drain the mip_rx_list if not empty */
		if (!skb_queue_empty_lockless(&con->mip_rx_list)) {
			get_con(con);
			if (!queue_work(con->srv->out2in_wq,
					&con->out2in_work)) {
				put_con(con);
			}
		}
		return -1;
	}

	/* SKB is in order, enqueue it and update con->next_recv while holding
         * the spinlock.
	 */
	spin_lock_bh(&con->mip_rx_list.lock);
	__skb_queue_tail(&con->mip_rx_list, skb);
	WRITE_ONCE(con->next_recv, seq + 1);
	spin_unlock_bh(&con->mip_rx_list.lock);

	/* Update local rcv window */
	update_local_rwnd(con);

	/* Send an ACK with the expected sequence */
	pepdna_minip_send_ack(con, READ_ONCE(con->next_recv), hdr->ts);

	pep_dbg("Sent ACK %u (rwnd %u bytes)", con->next_recv, con->local_rwnd);

	/* Schedule work to drain the mip_rx_list */
	get_con(con);
	if (!queue_work(con->srv->out2in_wq, &con->out2in_work)) {
		pep_dbg("Failed to queue out2in work");
		put_con(con);
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
	atomic_inc(&con->last_acked);
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
	[MIP_CON_REQ]   = pepdna_mip_recv_request,
	[MIP_CON_RESP]  = pepdna_mip_recv_response,
	[MIP_CON_DATA]  = pepdna_mip_recv_data,
	[MIP_CON_ACK]   = pepdna_mip_recv_ack,
	[MIP_CON_DEL]   = pepdna_mip_recv_delete,
	[MIP_CON_DONE]  = pepdna_mip_recv_done,
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
	return -EINVAL;
}


/*
 * can_forward - Determine how much can we forward from TCP to MIP
 * @con: Pointer to the connection structure
 *
 * Returns the number of bytes that the sender is allowed to forward.
 */
static int can_forward(struct pepcon *con, struct socket *sock)
{
	int unacked, rwnd;

	/* Check for EOF if red light */
	if (!READ_ONCE(con->sending)) {
		char peek_buf[1];  // Small buffer to actually read something
		struct msghdr msg = {
			.msg_flags = MSG_DONTWAIT | MSG_PEEK,
		};

		struct kvec vec = {
			.iov_base = peek_buf,
			.iov_len = 1,
		};

		pep_dbg("sending disabled, checking for EOF or FIN...");
		/* Perform a zero-byte read to detect connection closure */
		if (!kernel_recvmsg(sock, &msg, &vec, 1, 1, msg.msg_flags)) {
			pep_dbg("EOF detected: connection shutting down");
			return -ESHUTDOWN;
		}
		return 0;
	}

	unacked = atomic_read(&con->unacked) * MIP_MSS;
	rwnd = con->peer_rwnd;

	/* Calculate the effective rwnd taking into account the cwnd, receiver
         * rwnd, and in flight packets (unacked)
	 */
	int erwnd = rwnd - unacked;

	pep_dbg("CAN_FORWARD: sending=%d, cwnd=%u, unacked=%d, peer_rwnd=%u, erwnd=%d",
		READ_ONCE(con->sending), con->cwnd, unacked,
		con->peer_rwnd, erwnd);

	/* Check local congestion window */
	if (con->cwnd == 0)
		return 0;

	/* Check if peer has space for in flight packets */
	if(erwnd <= 0)
		return 0;

	return erwnd;
}


/*
 * Forward data from TCP socket to MINIP flow
 * ------------------------------------------------------------------------- */
static int pepdna_tcp2mip_fwd(struct pepcon *con, struct socket *from)
{
	int rx, tx, cwnd = can_forward(con, from);

	if (!cwnd) {
		pep_dbg("Cannot forward from TCP to MINIP, try -EAGAIN later");
		return -EAGAIN;
	} else if (cwnd < 0) {
		pep_dbg("conn id %u is shutting down...", con->id);
		return -1;
	}

	pep_dbg("About to read cwnd %d bytes from TCP sock to MINIP", cwnd);

	struct kvec vec = {
		.iov_base = con->rx_buff,
		.iov_len = cwnd,
	};
	struct msghdr msg = {
		.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL,
	};

	rx = kernel_recvmsg(from, &msg, &vec, 1, cwnd, MSG_DONTWAIT);
	pep_dbg("Attempting to forward %d bytes from TCP sock to MINIP", rx);
	if (rx > 0) {
		tx = pepdna_mip_send_data(con, con->rx_buff, rx);
		if (tx < 0) {
			pep_err("Failed to forward to MINIP flow");
			return -1;
		}
	}
	return rx;
}


/* TCP2MINIP
 * Forward traffic from INTERNET to MINIP
 * ------------------------------------------------------------------------- */
void pepdna_tcp2mip_work(struct work_struct *work)
{
	struct pepcon *con = container_of(work, struct pepcon, in2out_work);
	int rc;

	while (lconnected(con)) {
		if ((rc = pepdna_tcp2mip_fwd(con, con->lsock)) <= 0) {
			if (rc == -EAGAIN)
				break;
			/* Send a MIP_CON_DEL to deallocate the flow */
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

	skb_pull(skb, sizeof(struct miphdr));
	buff = (unsigned char *)skb->data;
	rx = ntohs(hdr->sdu_len);

	pep_dbg("Forwarding MIP seq %u of %d bytes to TCP", ntohl(hdr->seq), rx);

	tx = pepdna_sock_write(con->lsock, buff, rx);

	pep_dbg("Forwarded %d / %d bytes from MIP to TCP", tx, rx);

	return tx;
}


/*
 * MINIP2TCP
 * Forward traffic from MINIP to INTERNET
 * ------------------------------------------------------------------------- */
void pepdna_mip2tcp_work(struct work_struct *work)
{
	struct pepcon *con = container_of(work, struct pepcon, out2in_work);
	struct sk_buff *skb;
	struct sk_buff_head tmp;
	int rc;

	if (unlikely(!rconnected(con)))
		goto release;

	/* tmp doesn't need a spinlock since this work cannot run concurrently*/
	__skb_queue_head_init(&tmp);

	/* Splice all the mip_rx_list SKBs into a tmp list. Although this work
	 * cannot be launched concurrently, other threads may add skb to the
	 * list, therefore we need spinlock.
	 */
	spin_lock_bh(&con->mip_rx_list.lock);
	skb_queue_splice_init(&con->mip_rx_list, &tmp);
	spin_unlock_bh(&con->mip_rx_list.lock);

	if ((rc = skb_queue_len_lockless(&tmp)) == 0) {
		/* if conn is CLOSING and queue is empty => time to DELETE */
		if (READ_ONCE(con->state) == CLOSING) {
			/* Send a MIP_CON_DEL to deallocate the flow */
			pepdna_mip_send_delete(con);

			/* Just close the con and wait... */
			mod_timer(&con->rto_timer,
				  jiffies + msecs_to_jiffies(con->rto));
			close_con(con);
		}
		goto release;
	}

	/* FIXME: Update local rwnd */
	update_local_rwnd(con);

	/* Send ACK with old seq and 0 tstamp to notify the new rwnd ONLY if the
         * skb batch is > MIP_INIT_CWND
	 */
	if (rc > 3)
		pepdna_minip_send_ack(con, MIP_FIRST_SEQ, 0);

	/* Start draining the tmp queue */
	while ((skb = __skb_dequeue(&tmp))) {
		rc = pepdna_mip2tcp_fwd(con, skb);
		if (rc < 0) {
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
