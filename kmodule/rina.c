/*
 *	pep-dna/kmodule/rina.c: PEP-DNA RINA support
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

#ifdef CONFIG_PEPDNA_RINA
#include "rina.h"
#include "core.h"
#include "connection.h"
#include "netlink.h"
#include "tcp_utils.h"
#include "hash.h"

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)
#include <linux/signal.h>
#else
#include <linux/sched/signal.h>
#endif

#ifdef CONFIG_PEPDNA_LOCAL_SENDER
#include <net/ip.h>
#endif


/*
 * Check if RINA flow is not destroyed
 * ------------------------------------------------------------------------- */
bool flow_is_ok(struct ipcp_flow *flow)
{
	if (flow && flow->wqs &&
	    (flow->state == PORT_STATE_ALLOCATED || flow->state == PORT_STATE_DISABLED))
		return true;

	return false;
}

/*
 * Check if flow is readable
 * ------------------------------------------------------------------------- */
bool queue_is_ready(struct ipcp_flow *flow)
{
	if (!flow_is_ok(flow) || !rfifo_is_empty(flow->sdu_ready))
		return true;

	return false;
}

/*
 * Wait for RINA flow to become readable
 * ------------------------------------------------------------------------- */
long pepdna_wait_for_sdu(struct ipcp_flow *flow)
{
	DEFINE_WAIT(wq_entry);
	signed long timeo = (signed long)usecs_to_jiffies(FLOW_POLL_TIMEOUT);

	for (;;) {
		if (flow_is_ok(flow)) {
			prepare_to_wait(&flow->wqs->read_wqueue, &wq_entry,
					TASK_INTERRUPTIBLE);
		} else {
			timeo = -ESHUTDOWN;
			return timeo;
		}

		if (timeo && rfifo_is_empty(flow->sdu_ready)) {
			timeo = schedule_timeout(timeo);
		}
		if (!timeo || queue_is_ready(flow))
		break;

		if (signal_pending(current)) {
			timeo = -ERESTARTSYS;
			break;
		}
	}

	if (flow_is_ok(flow)) {
		finish_wait(&flow->wqs->read_wqueue, &wq_entry);
	} else {
		timeo = -ESHUTDOWN;
		__set_current_state(TASK_RUNNING);
	}

	return timeo;
}

/*
 * Send DUs over a RINA flow
 * ------------------------------------------------------------------------- */
static int pepdna_flow_write(struct ipcp_flow *flow, int pid, unsigned char *buf,
			     size_t len)
{
	struct ipcp_instance *ipcp = NULL;
	struct du *du		   = NULL;
	size_t left		   = len;
	size_t max_du_size	   = 0;
	size_t copylen		   = 0;
	size_t sent		   = 0;
	int rc			   = 0;

	if (!flow) {
		pep_err("No flow bound to port_id %d", pid);
		return -EBADF;
	}

	if (flow->state < 0) {
		pep_err("Flow with port_id %d is already deallocated", pid);
		return -ESHUTDOWN;
	}

	ipcp = flow->ipc_process;

	max_du_size = ipcp->ops->max_sdu_size(ipcp->data);

	while (left) {
		copylen = min(left, max_du_size);
		du = du_create(copylen);
		if (!du) {
			rc = -ENOMEM;
			goto out;
		}

		memcpy(du_buffer(du), buf + sent, copylen);

		if (ipcp->ops->du_write(ipcp->data, pid, du, false)) {
			pep_err("Couldn't write SDU to port_id %d", pid);
			rc = -EIO;
			goto out;
		}

		left -= copylen;
		sent += copylen;
	}
out:
		return sent ? sent : rc;
}


void pepdna_rina_flow_alloc(struct work_struct *work)
{
	struct pepcon *con = container_of(work, struct pepcon, connect_work);
	int rc = 0;

	/* Asking fallocator.client to initiate (1) a RINA flow allocation */
	rc = pepdna_nl_sendmsg(con->syn.saddr, con->syn.source,
			       con->syn.daddr, con->syn.dest,
			       con->id, atomic_read(&con->port_id), 1);
	if (rc < 0) {
		pep_err("Couldn't notify fallocator to allocate a flow");

		// Remove from hash table first (very important!)
		hash_del(&con->hlist);
		close_con(con);
		put_con(con);  // Release initial allocation reference
	}
}

/*
 * Check if flow has already a valid port-id and a !NULL flow
 * ------------------------------------------------------------------------- */
bool flow_is_ready(struct pepcon *con)
{
	struct ipcp_flow *flow = NULL;

	flow = kfa_flow_find_by_pid(kipcm_kfa(default_kipcm),
				    atomic_read(&con->port_id));
	if (flow) {
		pep_dbg("Flow with port_id %d is now ready",
			  atomic_read(&con->port_id));
		con->flow = flow;
		con->flow->state = PORT_STATE_ALLOCATED;
	} else {
		pep_dbg("Flow with port_id %d is not ready yet",
			  atomic_read(&con->port_id));
	}

	return flow && atomic_read(&con->port_id);
}

/*
 * Allocate wqs for the flow
 * ------------------------------------------------------------------------- */
static int pepdna_flow_set_iowqs(struct ipcp_flow *flow)
{
	struct iowaitqs *wqs = rkzalloc(sizeof(struct iowaitqs), GFP_KERNEL);
	if (!wqs)
		return -ENOMEM;

	init_waitqueue_head(&wqs->read_wqueue);
	init_waitqueue_head(&wqs->write_wqueue);

	flow->wqs = wqs;

	return 0;
}

/*
 * Forward data from RINA flow to TCP socket
 * ------------------------------------------------------------------------- */
int pepdna_con_rina2i_fwd(struct pepcon *con)
{
	struct kfa *kfa	     = kipcm_kfa(default_kipcm);
	struct socket *lsock = con->lsock;
	struct du *du        = NULL;
	int port_id	     = atomic_read(&con->port_id);
	bool blocking	     = false; /* Don't block while reading from the flow */
	signed long timeo    = 0;
	int rx = 0, tx   = 0;

	IRQ_BARRIER;

	while (rconnected(con)) {
		timeo = pepdna_wait_for_sdu(con->flow);
		if (timeo > 0)
			break;
		if (timeo == -ERESTARTSYS ||
		    timeo == -ESHUTDOWN || timeo == -EINTR)
			return -1;
	}

	rx = kfa_flow_du_read(kfa, port_id, &du, MAX_SDU_SIZE, blocking);
	if (rx <= 0) {
		pep_dbg("kfa_flow_du_read %d", rx);
		return rx;
	}

	if (!is_du_ok(du))
		return -EIO;

	tx = pepdna_sock_write(lsock, du_buffer(du), rx);
	if (tx < 0) {
		pep_dbg("Failed to forward %d bytes from flow to socket",
			rx);
		rx = -1;
	}

	du_destroy(du);
	return rx;
}

/*
 * Forward data from TCP socket to RINA flow
 * ------------------------------------------------------------------------- */
static int pepdna_con_i2rina_fwd(struct pepcon *con, struct socket *from,
				 struct ipcp_flow *to)
{
	struct msghdr msg;
	struct kvec vec;
	int rx, tx = 0;
	int port_id = atomic_read(&con->port_id);

	vec.iov_base = con->rx_buff;
	vec.iov_len  = MAX_BUF_SIZE;
	msg.msg_flags = MSG_DONTWAIT;

	rx = kernel_recvmsg(from, &msg, &vec, 1, vec.iov_len, MSG_DONTWAIT);
	if (likely(rx > 0)) {
		tx = pepdna_flow_write(to, port_id, con->rx_buff, rx);
		if (tx < 0) {
			pep_err("Failed to forward %d bytes to flow %d", rx, port_id);
			return tx;
		}
	}
	return rx;
}

/*
 * Netlink callback for RINA2TCP mode
 * ------------------------------------------------------------------------- */
void nl_r2i_callback(struct nl_msg *nlmsg)
{
	struct pepcon *con = NULL;
	struct synhdr *syn  = NULL;
	uint32_t hash_id;

	if (nlmsg->alloc) {
		syn = (struct synhdr *)kzalloc(sizeof(struct synhdr),
					       GFP_ATOMIC);
		if (IS_ERR(syn)) {
			pep_err("kzalloc");
			return;
		}
		syn->saddr  = cpu_to_be32(nlmsg->saddr);
		syn->source = cpu_to_be16(nlmsg->source);
		syn->daddr  = cpu_to_be32(nlmsg->daddr);
		syn->dest   = cpu_to_be16(nlmsg->dest);

		hash_id = pepdna_hash32_rjenkins1_2(syn->saddr, syn->source);
		con = init_con(syn, NULL, hash_id, 0ull, nlmsg->port_id);
		if (!con)
			pep_err("init_con");

		kfree(syn);
	} else {
		con = find_con(nlmsg->id);
		if (!con) {
			pep_err("Connection was removed from Hash Table");
			return;
		}
		if (flow_is_ready(con)) {
			/* At this point, right TCP connection is established
			 * and RINA flow is allocated. Queue r2i_work now!
			 */

			if (!con->flow->wqs)
				pepdna_flow_set_iowqs(con->flow);

			WRITE_ONCE(con->rflag, true);
			WRITE_ONCE(con->lflag, true);

			get_con(con);
			if (!queue_work(con->srv->out2in_wq, &con->out2in_work)) {
				pep_err("out2in_work was already on a queue");
				put_con(con);
				return;
			}
			/* Wake up 'left' socket */
			con->lsock->sk->sk_data_ready(con->lsock->sk);
		}
	}
}

/*
 * Netlink callback for TCP2RINA mode
 * ------------------------------------------------------------------------- */
void nl_i2r_callback(struct nl_msg *nlmsg)
{
	struct pepcon *con = NULL;

	con = find_con(nlmsg->id);
	if (!con) {
		pep_err("Connection not found in Hash table");
		return;
	}
	atomic_set(&con->port_id, nlmsg->port_id);

	if (flow_is_ready(con)) {
		WRITE_ONCE(con->rflag, true);

		if (!con->flow->wqs)
			pepdna_flow_set_iowqs(con->flow);

		/* At this point, RINA flow is allocated. Reinject SYN in back
		 * in the stack so that the left TCP connection can be
		 * established There is no need to set callbacks here for the
		 * left socket as pepdna_tcp_accept() will take care of it.
		 */
		pep_dbg("Reinjecting initial SYN packet");
#ifndef CONFIG_PEPDNA_LOCAL_SENDER
		netif_receive_skb(con->skb);
#else
		ip_local_out(sock_net(con->srv->listener->sk),
			     con->srv->listener->sk,
			     con->skb);
#endif
	}
}

/*
 * TCP2RINA
 * Forward traffic from INTERNET to RINA
 * ------------------------------------------------------------------------- */
void pepdna_con_i2r_work(struct work_struct *work)
{
	struct pepcon *con = container_of(work, struct pepcon, in2out_work);
	int rc = 0;

	while (lconnected(con)) {
		if ((rc = pepdna_con_i2rina_fwd(con, con->lsock, con->flow)) <= 0) {
			if (rc == -EAGAIN) //FIXME Handle -EAGAIN flood
				break;

			/* Ask userspace fallocator to dealloc. the flow */
			rc = pepdna_nl_sendmsg(0, 0, 0, 0, con->id,
					       atomic_read(&con->port_id), 0);
			if (rc < 0)
				pep_err("Flow deallocation failed");
			close_con(con);
		}
	}
	put_con(con);
}

/*
 * RINA2TCP
 * Forward traffic from RINA to INTERNET
 * ------------------------------------------------------------------------- */
void pepdna_con_r2i_work(struct work_struct *work)
{
	struct pepcon *con = container_of(work, struct pepcon, out2in_work);
	int rc = 0;

	while (rconnected(con)) {
		if ((rc = pepdna_con_rina2i_fwd(con)) <= 0) {
			if (rc == -EAGAIN)
				cond_resched();
			else
				close_con(con);
		}
	}
	put_con(con);
}
#endif
