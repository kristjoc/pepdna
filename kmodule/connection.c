/*
 *	pep-dna/kmodule/connection.c: PEP-DNA connection instance
 *
 *	Copyright (C) 2023	Kristjon Ciko <kristjoc@ifi.uio.no>
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

#include "connection.h"
#include "core.h"
#include "tcp.h"
#include "hash.h"

#ifdef CONFIG_PEPDNA_RINA
#include "rina.h"
#endif

#ifdef CONFIG_PEPDNA_MINIP
#include "minip.h"
#endif

#ifdef CONFIG_PEPDNA_CCN
#include "ccn.h"
#endif

#include <linux/sched.h>	/* included for wait_event_interruptible_timeout */
#include <net/sock.h>		/* included for struct sock */


/*
 * Check if left connection is active
 * ------------------------------------------------------------------------- */
bool lconnected(struct pepdna_con *con)
{
	return con && READ_ONCE(con->lflag);
}

/*
 * Check if right connection is active
 * ------------------------------------------------------------------------- */
bool rconnected(struct pepdna_con *con)
{
	return con && READ_ONCE(con->rflag);
}

static void pepdna_tcp_shutdown(struct work_struct *work)
{
	struct pepdna_con *con = container_of(work, struct pepdna_con, close_work);

	kernel_sock_shutdown(con->lsock, SHUT_RDWR);
}

#ifdef CONFIG_PEPDNA_MINIP
static void pepdna_create_thread(struct work_struct *work)
{
	struct pepdna_con *con = container_of(work, struct pepdna_con, start_work);

	atomic_set(&con->m2i_thread_running, 1);
	// Create forwarding thread for this connection
	con->m2i_thread = kthread_create(pepdna_m2i_fwd, con, "pepdna_m2i_fwd");
}
#endif

/*
 * Allocate a new pepdna_con and add it to the Hash Table
 * This function is called by the Hook func @'server.c'
 * ------------------------------------------------------------------------- */
struct pepdna_con *pepdna_con_alloc(struct syn_tuple *syn, struct sk_buff *skb,
				    uint32_t hash_id, uint64_t ts, int port_id)
{
	struct pepdna_con *con = kmalloc(sizeof(struct pepdna_con), GFP_ATOMIC);
	if (!con)
		return NULL;

	/* initialize refcount to 1 */
	kref_init(&con->kref);
	con->skb = (skb) ? skb_copy(skb, GFP_ATOMIC) : NULL;

	switch (pepdna_srv->mode) {
	case TCP2TCP:
		INIT_WORK(&con->in2out_work, pepdna_tcp_in2out_work);
		INIT_WORK(&con->out2in_work, pepdna_tcp_out2in_work);
		INIT_WORK(&con->connect_work, pepdna_tcp_connect);
		INIT_WORK(&con->close_work, pepdna_tcp_shutdown);
		break;
#ifdef CONFIG_PEPDNA_RINA
	case TCP2RINA:
		INIT_WORK(&con->in2out_work, pepdna_con_i2r_work);
		INIT_WORK(&con->out2in_work, pepdna_con_r2i_work);
		INIT_WORK(&con->connect_work, pepdna_rina_flow_alloc);
		INIT_WORK(&con->close_work, pepdna_tcp_shutdown);
		break;
	case RINA2TCP:
		INIT_WORK(&con->in2out_work, pepdna_con_i2r_work);
		INIT_WORK(&con->out2in_work, pepdna_con_r2i_work);
		INIT_WORK(&con->connect_work, pepdna_tcp_connect);
		INIT_WORK(&con->close_work, pepdna_tcp_shutdown);
		break;
	case RINA2RINA:
		/* INIT_WORK(&con->in2out_work, pepdna_con_rl2rr_work); */
		/* INIT_WORK(&con->out2in_work, pepdna_con_rr2rl_work); */
		/* INIT_WORK(&con->connect_work, pepdna_rina_flow_alloc); */
		break;
#endif
#ifdef CONFIG_PEPDNA_MINIP
	case TCP2MINIP:
		INIT_WORK(&con->in2out_work, pepdna_con_i2m_work);
		INIT_WORK(&con->out2in_work, pepdna_con_m2i_work);
		INIT_WORK(&con->connect_work, pepdna_minip_handshake);
		INIT_WORK(&con->close_work, pepdna_tcp_shutdown);
		INIT_WORK(&con->start_work, pepdna_create_thread);
		break;
	case MINIP2TCP:
		INIT_WORK(&con->in2out_work, pepdna_con_i2m_work);
		INIT_WORK(&con->out2in_work, pepdna_con_m2i_work);
		INIT_WORK(&con->connect_work, pepdna_tcp_connect); // FIXME
		INIT_WORK(&con->close_work, pepdna_tcp_shutdown);
		INIT_WORK(&con->start_work, pepdna_create_thread);
		break;
#endif
#ifdef CONFIG_PEPDNA_CCN
	case TCP2CCN:
		INIT_WORK(&con->in2out_work, pepdna_con_i2c_work);
		INIT_WORK(&con->out2in_work, pepdna_con_c2i_work);
		INIT_WORK(&con->connect_work, pepdna_udp_open);
		INIT_WORK(&con->close_work, pepdna_tcp_shutdown);
		break;
	case CCN2TCP:
		/* TODO: Not supported yet! */
		/* INIT_WORK(&con->in2out_work, pepdna_con_c2i_work); */
		/* INIT_WORK(&con->out2in_work, pepdna_con_i2c_work); */
		break;
	case CCN2CCN:
		/* TODO: Not supported yet*/
		/* INIT_WORK(&con->in2out_work, pepdna_con_lc2rc_work); */
		/* INIT_WORK(&con->out2in_work, pepdna_con_rc2lc_work); */
		break;
#endif
	default:
		pep_err("pepdna mode undefined");
		return NULL;
	}

	con->id = hash_id;
	con->ts = ts;
#ifdef CONFIG_PEPDNA_RINA
	atomic_set(&con->port_id, port_id);
	con->flow = NULL;
#endif
#ifdef CONFIG_PEPDNA_MINIP
        con->next_seq = MINIP_FIRST_SEQ;
        atomic_set(&con->last_acked, MINIP_FIRST_SEQ);
        con->next_recv = MINIP_FIRST_SEQ;
	con->window = WINDOW_SIZE;

	/* Initialize the MINIP rx queue */
	skb_queue_head_init(&con->mrxq);
	spin_lock_init(&con->mrxq_lock);
	atomic_set(&con->mrxq_len, 0);
	
        /* Create the retransmission queue for MINIP flow control */
        con->rtxq = rtxq_create();
        if (!con->rtxq) {
                pep_err("Failed to create rtxq instance");
                kfree(con);
                return NULL;
        }
	WRITE_ONCE(con->sending, true);
	/* Initialize dup_acks counter to 0 */
        atomic_set(&con->dup_acks, 0);
	atomic_set(&con->unacked_count, 0);

        /* RTO initial value is 3 seconds.
	 * Details in Section 2.1 of RFC6298
	 */
	con->rto = 3000;
	con->srtt = 0;
	con->rttvar = 0;

	timer_setup(&con->timer, minip_sender_timeout, 0);
#endif
	timer_setup(&con->timer, tcp_con_timeout, 0);

	con->server = pepdna_srv;
	atomic_inc(&con->server->conns);
	con->lsock	= NULL;
	con->rsock	= NULL;

#ifdef CONFIG_PEPDNA_MINIP
	schedule_work(&con->start_work);
#endif
	/* Alocate per-connection rx buffer */
	con->rx_buff = kmalloc(MAX_BUF_SIZE, GFP_ATOMIC);
	if (!con->rx_buff) {
		pep_err("Failed to allocate con->rx_buff");
		/* Free previously allocated resources */
		kfree(con);
		return NULL;
	}
	
	WRITE_ONCE(con->lflag, false);
	WRITE_ONCE(con->rflag, false);

	con->tuple.saddr  = syn->saddr;
	con->tuple.source = syn->source;
	con->tuple.daddr  = syn->daddr;
	con->tuple.dest	  = syn->dest;

	INIT_HLIST_NODE(&con->hlist);
	hash_add(pepdna_srv->htable, &con->hlist, con->id);

	schedule_work(&con->connect_work);

	return con;
}

/*
 * Find connection in Hash Table
 * Called by: pepdna_tcp_accept() @'tcp_listen.c'
 *		  nl_r2i_callback() @'server.c'
 * ------------------------------------------------------------------------- */
struct pepdna_con *pepdna_con_find(uint32_t key)
{
	struct pepdna_con* con	 = NULL;
	struct pepdna_con* found = NULL;
	struct hlist_head *head	 = NULL;
	struct hlist_node *next;

	rcu_read_lock();
	head = &pepdna_srv->htable[pepdna_hash(pepdna_srv->htable, key)];
	hlist_for_each_entry_safe(con, next, head, hlist) {
		if (con->id == key) {
			found = con;
			break;
		}
	}
	rcu_read_unlock();

	return found;
}


/*
 * Close Connection => Flow
 * ------------------------------------------------------------------------- */
void pepdna_con_close(struct pepdna_con *con)
{
        struct sock *lsk = NULL;
        struct sock *rsk = NULL;
        bool lconnected  = false;
        bool rconnected  = false;
#ifdef CONFIG_PEPDNA_RINA
        struct ipcp_flow *flow = (con) ? con->flow : NULL;
#endif

        if (!con) {
		pep_dbg("Oops, con is being closed but is already NULL");
		return;
        }

        lsk = (con->lsock) ? con->lsock->sk : NULL;
        if (!lsk)
                return;

        lconnected = READ_ONCE(con->lflag);
        rconnected = READ_ONCE(con->rflag);

        /* Close Left side */
        WRITE_ONCE(con->lflag, false);
        write_lock_bh(&lsk->sk_callback_lock);
        if (lconnected)
                lsk->sk_user_data = NULL;
        write_unlock_bh(&lsk->sk_callback_lock);

	/* Queue connection termination work */
        if (lconnected) {
		schedule_work(&con->close_work);
	}

        /* Close Right side (might be TCP, RINA, CCN, or MINIP) */
        if (con->server->mode == TCP2TCP) {
                rsk = (con->rsock) ? con->rsock->sk : NULL;
                if (!rsk)
                        return;

		WRITE_ONCE(con->rflag, false);
                write_lock_bh(&rsk->sk_callback_lock);
                if (rconnected)
                        rsk->sk_user_data = NULL;
                write_unlock_bh(&rsk->sk_callback_lock);

                kernel_sock_shutdown(con->rsock, SHUT_RDWR);

		mod_timer(&con->timer, jiffies + msecs_to_jiffies(TCP_ZOMBIE_TIMEOUT));
        } else {
#ifdef CONFIG_PEPDNA_RINA
                WRITE_ONCE(con->rflag, false);
                if (rconnected) {
                        if (flow && flow->wqs)
                                wake_up_interruptible_all(&flow->wqs->read_wqueue);

                        cancel_work_sync(&con->out2in_work);
			pep_dbg("RINA out2in_work cancelled");
                }
#endif
#ifdef CONFIG_PEPDNA_MINIP
		// Check if we're already in CLOSING, ZOMBIE or FINISHED state
                u8 state = READ_ONCE(con->state);
                if (state == CLOSING || state == ZOMBIE || state == FINISHED) {
                        pep_dbg("conn id %u already in CLOSING state", con->id);
                        return;
                } else {
                        // Cancel any work in progress
                        /* cancel_work_sync(&con->out2in_work); */
			// Signal thread to stop and wait for it
			atomic_set(&con->m2i_thread_running, 0);
			kthread_stop(con->m2i_thread);
                        
                        // Note: We don't directly move to ZOMBIE here
                        // The state change to CLOSING or ZOMBIE should be done by the caller
                        return;
                }
#endif
	}
}

/*
 * Release connection after pepdna_con_put(con) is called
 * ------------------------------------------------------------------------- */
static void pepdna_con_kref_release(struct kref *kref)
{
	struct pepdna_con *con = container_of(kref, struct pepdna_con, kref);
	if (!con) {
		pep_dbg("conn already released and freed");
		return;
	}

	if (con->lsock) {
		sock_release(con->lsock);
		con->lsock = NULL;
	}
	if (con->rsock) {
		sock_release(con->rsock);
		con->rsock = NULL;
	}

	hlist_del(&con->hlist);
	kfree(con->rx_buff);
#ifdef CONFIG_PEPDNA_MINIP
	// The rtxq should have been cleaned in the ZOMBIE timeout handler
	if (con->rtxq) {
		pep_warn("rtxq still exists during final cleanup for conn %u", con->id);
		rtxq_destroy(con->rtxq);
	}

	// Check if mrxq is empty
	if (!skb_queue_empty(&con->mrxq)) {
		pep_warn("mrxq not empty during final cleanup for conn %u", con->id);
		spin_lock_bh(&con->mrxq_lock);
		__skb_queue_purge(&con->mrxq);
		spin_unlock_bh(&con->mrxq_lock);
	}
#endif
	// Now free the connection structure
	pep_dbg("conn id %u fully released and freed", con->id);
	con->id = 0xDEADBEEF;  // Mark as fully deleted for debugging
	atomic_dec(&pepdna_srv->conns);
	kfree(con); con = NULL;
}

/*
 * Release the reference of connection instance
 * ------------------------------------------------------------------------- */
void pepdna_con_put(struct pepdna_con *con)
{
	if (!con)
		return;

	/* Track who's decrementing the refcount */
	pep_dbg("REF-- con %p: count %d -> %d from %pS", 
		con, kref_read(&con->kref), kref_read(&con->kref) - 1,
		__builtin_return_address(0));

	if (kref_read(&con->kref) > 0)
		kref_put(&con->kref, pepdna_con_kref_release);
	else
		pep_err("REFCOUNT ERROR: Attempt to put con %p with zero refcount", con);
}

/*
 * Get reference to connection instance
 * ------------------------------------------------------------------------- */
void pepdna_con_get(struct pepdna_con *con)
{
	if (!con)
		return;

	/* Track who's incrementing the refcount */
	pep_dbg("REF++ con %p: count %d -> %d from %pS", 
		con, kref_read(&con->kref), kref_read(&con->kref) + 1,
		__builtin_return_address(0));

	kref_get(&con->kref);
}
