#ifndef _PEPDNA_MIP_H
#define _PEPDNA_MIP_H

#ifdef CONFIG_PEPDNA_MINIP
#include <linux/workqueue.h>
#include <linux/timer.h>

#include "connection.h"

#define ETH_ALEN      6
#define ETH_P_MINIP   0x88FF
#define ETH_BROADCAST { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }


/**
 * MIP_FIRST_SEQ - First seq number of each connection
 */
#define MIP_FIRST_SEQ 1u

/**
 * MIP_INIT_CWND - Initial congestion window
 */
#define MIP_INIT_CWND 10u

/**
 * MIP_ZOMBIE_TIMEOUT - Wait 30s after a connection is closed, where
 * the system waits for a period to ensure that all packets have been
 * properly acknowledged
 */
#define MIP_ZOMBIE_TIMEOUT 30000u

/* Define handler type */
typedef int (*pkt_handler_t)(struct sk_buff *);

/**
 * struct miphdr - MIP protocol header (23 bytes)
 * @pkt_type:      MIP packet type
 * @sdu_len:       SDU length in bytes
 * @cid:           hash(src IP, src port, dst IP, dst port)
 * @seq:           sequence number
 * @ack:           acknowledge number
 * @rwnd:          receive window size in bytes
 * @ts:            time when the packet has been sent
 */
struct miphdr {
	u8  pkt_type;
	u32 id;
	u32 seq;
	u16 sdu_len;
	u32 ack;
	u32 rwnd;
	__be32 ts;
} __attribute__ ((packed));


/**
 * get_pkt_type_prefetch - Get packet type with prefetching
 * @hdr: Pointer to MIP header
 *
 * Prefetches the header and returns the packet type
 */
static inline u8 get_pkt_type_prefetch(const struct miphdr *hdr)
{
	/* Prefetch for read (0) with high temporal locality */
	__builtin_prefetch(hdr, 0, 3);

	return hdr->pkt_type;
}


/**
 * enum mip_pkt_type - MIP packet type
 * @MIP_CON_REQ:       SYN
 * @MIP_CON_RESP:      SYN/ACK
 * @MIP_CON_DEL:       FIN
 * @MIP_CON_DONE:      FIN/ACK
 * @MIP_CON_DATA:      DATA
 * @MIP_CON_ACK:       ACK
 */
enum mip_pkt_type {
	MIP_CON_REQ  = 0x01,
	MIP_CON_RESP = 0x02,
	MIP_CON_DEL  = 0x03,
	MIP_CON_DONE = 0x04,
	MIP_CON_DATA = 0x05,
	MIP_CON_ACK  = 0x06
};

/**
 * enum minip_state - MIP connection state
 * @REQ_SENT
 * @REQ_RECVD
 * @ESTABLISHED
 * @RECOVERY
 * @CLOSING
 * @FINISHED
 * @ZOMBIE
 */
enum minip_state {
	REQ_SENT    = 0x01,
	REQ_RECVD   = 0x02,
	ESTABLISHED = 0x03,
	RECOVERY    = 0x04,
	CLOSING     = 0x05,
	FINISHED    = 0x06,
	ZOMBIE      = 0x07
};

int pepdna_mip_send_response(struct pepcon *);
int pepdna_mip_recv_packet(struct sk_buff *);
void pepdna_mip_handshake(struct work_struct *);
void pepdna_tcp2mip_work(struct work_struct *);
void pepdna_mip2tcp_work(struct work_struct *);
void minip_zombie_timeout(struct timer_list *);
void minip_rto_timeout(struct timer_list *);

#endif /* CONFIG_PEPDNA_MINIP */

#endif /* _PEPDNA_MIP_H */
