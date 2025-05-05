/*
 *	pep-dna/kmodule/connection.h: PEP-DNA connection instance header
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

#ifndef _PEPDNA_CONNECTION_H
#define _PEPDNA_CONNECTION_H

#include "server.h"

#include <linux/kref.h>
#include <linux/netfilter.h>

#ifdef CONFIG_PEPDNA_RINA
struct ipcp_flow;
/* timeout for RINA flow allocation in msec */
#define FLOW_ALLOC_TIMEOUT 3000
#endif

/* timeout for TCP connection in msec */
#define TCP_ACCEPT_TIMEOUT 3000

#define pepdna_hash(T, K) hash_min(K, HASH_BITS(T))

extern struct pepsrv *pepdna_srv;

/**
 * struct synhdr - 4-tuple of syn packet
 * @saddr	 - source IP address
 * @ source      - source TCP port
 * @daddr	 - destination IP address
 * @dest	 - destination TCP port
 */
struct synhdr {
	__be32 saddr;
	__be16 source;
	__be32 daddr;
	__be16 dest;
};

/**
 * struct pepcon - pepdna connection struct
 * @kref:	   reference counter to connection object
 * @server:	   pointer to connected KPROXY server
 * @connect_work:  TCP connect/RINA Flow Allocation after accept work item
 * @in2out_work:   inbound 2 outbound work item
 * @out2in_work:   outbound 2 inbound work item
 * @close_work:    shutdown work to close connection
 * @hlist:	   node member in hash table
 * @flow:	   RINA flow
 * @port_id:       port id of the flow
 * @rtxq:          MINIP retransmission queue
 * @lsock:	   left TCP socket
 * @rsock:	   right TCP socket
 * @rx_buff:       pre-allocated rx buffer
 * @lflag:	   indicates left connection state
 * @rflag:	   indicates left connection state
 * @id:            32-bit hash connection identifier
 * @ts:		   timestamp of the first incoming SYN
 * @syn:	   connection tuple
 * @skb:	   initial SYN sk_buff
 */
struct pepcon {
	struct kref kref;
	struct pepsrv *srv;
	struct work_struct connect_work;
	struct work_struct in2out_work;
	struct work_struct out2in_work;
	struct work_struct close_work;
	struct hlist_node hlist;
#ifdef CONFIG_PEPDNA_RINA
	struct ipcp_flow *flow;
	atomic_t port_id;
#endif
#ifdef CONFIG_PEPDNA_MINIP
	/* sender variables */
	struct timer_list rto_timer;
	/** @mip_rx_list: per-connection queue for incoming MIP->TCP SKBs */
	struct sk_buff_head mip_rx_list;
	/** @mip_rtx_list: sender's retransmission queue */
	struct sk_buff_head mip_rtx_list;
	/** @dup_acks: duplicate ACKs counter */
	atomic_t dup_acks;
	/** @sending: sending binary semaphore: 1 if sending, 0 is not */
	bool sending;
	/** @last_acked: last acked packet */
	atomic_t last_acked;
	/** @dupACK: potential duplicate ACK */
	atomic_t dupACK;
	/** @next_seq: next packet to be sent */
        u32 next_seq;
	/** @unacked: nr of unacked packets */
	atomic_t unacked;
	/** @state: connection state */
        u8 state;
	/** @cwnd: congestion window */
        u16 cwnd;
	/* receiver variables */
	/** @next_recv: next in-order packet expected */
	u32 next_recv;
        /** @rto: sender timeout in milliseconds */
	u32 rto;
	/** @srtt: smoothed RTT scaled by 2^3 */
	u32 srtt;
	/** @rttvar: RTT variation scaled by 2^2 */
	u32 rttvar;
	u32 peer_rwnd;
	u32 local_rwnd;
#endif
	struct timer_list zombie_timer;
	struct socket *lsock;
	struct socket *rsock;
	struct synhdr syn;
	struct sk_buff *skb;
	unsigned char *rx_buff;
	bool lflag;
	bool rflag;
	u32 id;
	u64 ts;
};

bool lconnected(struct pepcon *);
bool rconnected(struct pepcon *);
struct pepcon *init_con(struct synhdr *, struct sk_buff *, u32,  u64, int);
struct pepcon *find_con(u32);
void get_con(struct pepcon *);
void put_con(struct pepcon *);
void close_con(struct pepcon *);

#endif /* _PEPDNA_CONNECTION_H */
