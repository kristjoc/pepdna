/*
 *	pep-dna/kmodule/connection.c: PEP-DNA connection instance
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

#include "connection.h"
#include "core.h"
#include "tcp.h"
#include "hash.h"

#ifdef CONFIG_PEPDNA_RINA
#include "rina.h"
#endif

#ifdef CONFIG_PEPDNA_MINIP
#include "mip.h"
#endif

#ifdef CONFIG_PEPDNA_CCN
#include "ccn.h"
#endif

#include <linux/sched.h>	/* included for wait_event_interruptible_timeout */
#include <net/sock.h>		/* included for struct sock */


static void pepdna_tcp_shutdown(struct work_struct *work)
{
	struct pepcon *con = container_of(work, struct pepcon, close_work);

	kernel_sock_shutdown(con->lsock, SHUT_RDWR);
}


/*
 * Allocate a new pepcon and add it to the Hash Table
 * This function is called by the Hook func @'server.c'
 * ------------------------------------------------------------------------- */
struct pepcon *init_con(struct synhdr *syn, struct sk_buff *skb, u32 hash_id,
			u64 ts, int port_id)
{
	struct pepcon *con = kmalloc(sizeof(struct pepcon), GFP_ATOMIC);
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
		INIT_WORK(&con->in2out_work, pepdna_tcp2mip_work);
		INIT_WORK(&con->out2in_work, pepdna_mip2tcp_work);
		INIT_WORK(&con->connect_work, pepdna_mip_handshake);
		INIT_WORK(&con->close_work, pepdna_tcp_shutdown);
		break;
	case MINIP2TCP:
		INIT_WORK(&con->in2out_work, pepdna_tcp2mip_work);
		INIT_WORK(&con->out2in_work, pepdna_mip2tcp_work);
		INIT_WORK(&con->connect_work, pepdna_tcp_connect); // FIXME
		INIT_WORK(&con->close_work, pepdna_tcp_shutdown);
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
	/* Initialize seq numbers */
        con->next_seq = MIP_FIRST_SEQ;
        atomic_set(&con->last_acked, MIP_FIRST_SEQ);
        atomic_set(&con->dupACK, MIP_FIRST_SEQ);
        atomic_set(&con->unacked, 0);
        con->next_recv = MIP_FIRST_SEQ;

	/* Initialize flow control */
	con->cwnd = MIP_INIT_CWND;
	con->peer_rwnd = MAX_BUF_SIZE;    /* Initial peer rwnd (e.g., 65535) */
	con->local_rwnd = MAX_BUF_SIZE;   /* Initial local rwnd (e.g., 65535) */
	atomic_set(&con->dup_acks, 0);
	WRITE_ONCE(con->sending, true);

	/* Initialize the MIP rx and rtx lists */
	skb_queue_head_init(&con->mip_rx_list);
	skb_queue_head_init(&con->mip_rtx_list);

        /* RTO initial value is 3 seconds.
	 * Details in Section 2.1 of RFC6298
	 */
	con->rto = 3000;
	con->srtt = 0;
	con->rttvar = 0;
#endif
#ifdef CONFIG_PEPDNA_MINIP
	timer_setup(&con->rto_timer, minip_rto_timeout, 0);
	timer_setup(&con->zombie_timer, minip_zombie_timeout, 0);
#else
	timer_setup(&con->zombie_timer, tcp_zombie_timeout, 0);
#endif
	con->srv = pepdna_srv;
	atomic_inc(&con->srv->conns);
	con->lsock = NULL;
	con->rsock = NULL;

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

	con->syn.saddr  = syn->saddr;
	con->syn.source = syn->source;
	con->syn.daddr  = syn->daddr;
	con->syn.dest	= syn->dest;

	INIT_HLIST_NODE(&con->hlist);
	hash_add_rcu(pepdna_srv->htable, &con->hlist, con->id);

	schedule_work(&con->connect_work);

	return con;
}

/**
 * find_con - Lookup a connection by key in the pepdna_srv hash table
 * @key: Connection identifier key
 *
 * Returns pointer to struct pepcon if found, NULL otherwise.
 * Uses RCU for safe concurrent access.
 */
struct pepcon *find_con(u32 key)
{
	struct pepcon *con, *found = NULL;

	rcu_read_lock();
	hash_for_each_possible_rcu(pepdna_srv->htable, con, hlist, key)
	{
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
void close_con(struct pepcon *con)
{
        struct sock *lsk, *rsk;
        bool lconnected, rconnected;
#ifdef CONFIG_PEPDNA_RINA
        struct ipcp_flow *flow = (con) ? con->flow : NULL;
#endif
        if (!con) {
		pep_dbg("Oops, attempting to close NULL con!!!");
		return;
        }

	if (!(lsk = (con->lsock) ? con->lsock->sk : NULL))
		return;


	lconnected = READ_ONCE(con->lflag);
	rconnected = READ_ONCE(con->rflag);

	/* Close inbound connection first */
	WRITE_ONCE(con->lflag, false);
	write_lock_bh(&lsk->sk_callback_lock);
	if (lconnected)
		lsk->sk_user_data = NULL;
	write_unlock_bh(&lsk->sk_callback_lock);

	/* Queue connection termination work */
	if (lconnected)
		schedule_work(&con->close_work);

	/* Close outbound connection (might be TCP, RINA, CCN, or MIP) */
	if (con->srv->mode == TCP2TCP) {
		if (!(rsk = (con->rsock) ? con->rsock->sk : NULL))
			return;

		WRITE_ONCE(con->rflag, false);
		write_lock_bh(&rsk->sk_callback_lock);
		if (rconnected)
			rsk->sk_user_data = NULL;
		write_unlock_bh(&rsk->sk_callback_lock);

		kernel_sock_shutdown(con->rsock, SHUT_RDWR);

		mod_timer(&con->zombie_timer,
			  jiffies + msecs_to_jiffies(TCP_ZOMBIE_TIMEOUT));
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
		/* We don't have to do anything here.
		 * Caller will switch to CLOSING/FINISHED/ZOMBIE state.
		 */

		/* Check if state > 4 => CLOSING(5), FINISHED(6), ZOMBIE(7) */
		u8 state = READ_ONCE(con->state);
		if (state > 4) {
			pep_dbg("conn id %u already in CLOSING state", con->id);
		}
#endif
	}
}

/*
 * Release connection after put_con(con) is called
 * ------------------------------------------------------------------------- */
static void pepdna_con_kref_release(struct kref *kref)
{
	struct pepcon *con = container_of(kref, struct pepcon, kref);
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

	if (con->rx_buff) {
		pep_dbg("kfreeing rx_buff for conn id %u", con->id);
		kfree(con->rx_buff);
		con->rx_buff = NULL;
	}

	pep_dbg("conn id %u is now 0xDEADBEEF", con->id);

	con->id = 0xDEADBEEF;  // Mark as fully deleted for debugging
	hash_del_rcu(&con->hlist);
	atomic_dec(&pepdna_srv->conns);

#ifdef CONFIG_PEPDNA_MINIP
	/* Purge MIP rx list */
	spin_lock_bh(&con->mip_rx_list.lock);
	__skb_queue_purge(&con->mip_rx_list);
	spin_unlock_bh(&con->mip_rx_list.lock);

	/* Purge MIP rtx list */
	spin_lock_bh(&con->mip_rtx_list.lock);
	__skb_queue_purge(&con->mip_rtx_list);
	spin_unlock_bh(&con->mip_rtx_list.lock);
#endif
	// Now free the connection structure
	kfree_rcu(con, rcu);
}

/*
 * Release the reference of connection instance
 * ------------------------------------------------------------------------- */
void put_con(struct pepcon *con)
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
void get_con(struct pepcon *con)
{
	if (!con)
		return;

	/* Track who's incrementing the refcount */
	pep_dbg("REF++ con %p: count %d -> %d from %pS", 
		con, kref_read(&con->kref), kref_read(&con->kref) + 1,
		__builtin_return_address(0));

	kref_get(&con->kref);
}
