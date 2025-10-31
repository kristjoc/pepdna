/*
 *	pep-dna/kmodule/server.c: PEP-DNA server infrastructure
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

#include "core.h"
#include "server.h"
#include "tcp.h"
#include "connection.h"
#include "tcp_utils.h"
#include "netlink.h"
#include "hash.h"

#ifdef CONFIG_PEPDNA_RINA
#include "rina.h"
#endif

#ifdef CONFIG_PEPDNA_CCN
#include "ccn.h"
#endif

#ifdef CONFIG_PEPDNA_MINIP
#include "mip.h"
#include <linux/etherdevice.h>
#endif

#include <linux/kthread.h>
#include <linux/in.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define SSH_PORT 22

/* External variables */
extern int mode;
extern int port;
#ifdef CONFIG_PEPDNA_MINIP
extern char *ifname;
extern char *mac;
#endif

/* Global variables */
struct pepsrv *pepdna_srv = NULL;

/* Static functions */
static unsigned int pepdna_pre_hook(void *, struct sk_buff *,
				    const struct nf_hook_state *);
#ifdef CONFIG_PEPDNA_MINIP
struct packet_type minip;
static int pepdna_mip_recv_skb(struct sk_buff *skb, struct net_device *dev,
			       struct packet_type *pt, struct net_device *orig_dev);
#endif
static void init_pepdna_server(struct pepsrv *);
static int pepdna_i2i_start(struct pepsrv *);
#ifdef CONFIG_PEPDNA_RINA
static int pepdna_r2r_start(struct pepsrv *);
static int pepdna_r2i_start(struct pepsrv *);
static int pepdna_i2r_start(struct pepsrv *);
#endif
#ifdef CONFIG_PEPDNA_MINIP
static int pepdna_m2i_start(struct pepsrv *);
static int pepdna_i2m_start(struct pepsrv *);
#endif
#ifdef CONFIG_PEPDNA_CCN
static int pepdna_i2c_start(struct pepsrv *);
static int pepdna_c2i_start(struct pepsrv *);
#endif

/*
 * Init workqueue_struct
 * This function is called by pepdna_from2to_start() @'server.c'
 * ------------------------------------------------------------------------- */
static int pepdna_work_init(struct pepsrv *srv)
{
	if (!srv) {
		pep_err("Invalid pepsrv pointer");
		return -ENOENT;
	}

	/* srv->in2out_wq = alloc_workqueue("in2out_wq", WQ_HIGHPRI | WQ_CPU_INTENSIVE, 0); */
	srv->in2out_wq = alloc_workqueue("in2out_wq", WQ_HIGHPRI | WQ_UNBOUND, 0);
	/* srv->in2out_wq = alloc_ordered_workqueue("in2out_wq", 0); */
	if (!srv->in2out_wq) {
		pep_err("Failed to allocate in2out workqueue");
		return -ENOMEM;
	}

	/* srv->out2in_wq = alloc_workqueue("out2in_wq", WQ_HIGHPRI | WQ_CPU_INTENSIVE, 0); */
	srv->out2in_wq = alloc_workqueue("out2in_wq", WQ_HIGHPRI | WQ_UNBOUND, 0);
	/* srv->out2in_wq = alloc_ordered_workqueue("out2in_wq", 0); */
	if (!srv->out2in_wq) {
		pep_err("Failed to allocate out2in workqueue");
		destroy_workqueue(srv->in2out_wq);
		return -ENOMEM;
	}

	return 0;
}

/**
 * pepdna_work_stop - Stop and clean up all workqueues
 * @srv: Server structure containing workqueues to stop
 *
 * Flushes and destroys all active workqueues in the server structure.
 * Safe to call even if workqueues are NULL.
 */
static void pepdna_work_stop(struct pepsrv *srv)
{
	/* Clean up in2out workqueue */
	if (srv->in2out_wq) {
		pep_dbg("Stopping in2out workqueue");
		flush_workqueue(srv->in2out_wq);
		destroy_workqueue(srv->in2out_wq);
		srv->in2out_wq = NULL;
	}

	/* Clean up out2in workqueue */
	if (srv->out2in_wq) {
		pep_dbg("Stopping out2in workqueue");
		flush_workqueue(srv->out2in_wq);
		destroy_workqueue(srv->out2in_wq);
		srv->out2in_wq = NULL;
	}
}

/* pepdna_con_data_ready - interrupt callback indicating the socket has data
 * The queued work is launched into ?
 * ------------------------------------------------------------------------- */
void pepdna_in2out_data_ready(struct sock *sk)
{
	struct pepcon *con = READ_ONCE(sk->sk_user_data);
	if (!con)
		return;

	pep_dbg("in-bound data ready %p", sk);

	if (likely(lconnected(con))) {
		get_con(con);
		if (!queue_work(con->srv->in2out_wq, &con->in2out_work)) {
			pep_dbg("in2out work already on a queue");
			put_con(con);
		}
	}
}

/* pepdna_con_data_ready - interrupt callback indicating the socket has data
 * The queued work is launched into ?
 * ------------------------------------------------------------------------- */
void pepdna_out2in_data_ready(struct sock *sk)
{
	struct pepcon *con = READ_ONCE(sk->sk_user_data);
	if (!con)
		return;

	pep_dbg("out-bound data ready %p\n", sk);

	if (likely(rconnected(con))) {
		get_con(con);
		if (!queue_work(con->srv->out2in_wq, &con->out2in_work)) {
			put_con(con);
		}
	}
}

static unsigned int pepdna_pre_hook(void *priv, struct sk_buff *skb,
				    const struct nf_hook_state *state)
{
	struct pepcon *con;
	struct synhdr *syn;
	const struct iphdr *iph;
	const struct tcphdr *tcph;
	u32 hash_id;
	u64 ts;

	if (!skb)
		return NF_ACCEPT;
	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		/* Check for packets with ONLY SYN flag set */
		if (tcph->syn == 1 && tcph->ack == 0 && tcph->rst == 0) {
#if defined(CONFIG_PEPDNA_LOCAL_SENDER) || defined(CONFIG_PEPDNA_LOCAL_RECEIVER)
			/* When PEP-DNA runs at the sender/receiver host, do
			 * not filter the SYN packets which are sent
			 * by pepdna_tcp_connect() */
			if (skb->mark == PEPDNA_SOCK_MARK)
				return NF_ACCEPT;
#endif
			/* Exclude SSH, 80, and 5565 temporarily */
			if (ntohs(tcph->dest) == SSH_PORT ||
			    ntohs(tcph->dest) == 5665 ||
			    ntohs(tcph->dest) == 80)
				return NF_ACCEPT;

			hash_id = pepdna_hash32_rjenkins1_2(iph->saddr,
							    tcph->source);

			con = find_con(hash_id);
			if (!con) {
				/* conn id not found, this is a new request */
				syn = kmalloc(sizeof(*syn), GFP_ATOMIC);
				if (!syn) {
					pep_err("Failed to allocate synhdr");
					return NF_DROP;
				}
				syn->saddr  = iph->saddr;
				syn->source = tcph->source;
				syn->daddr  = iph->daddr;
				syn->dest   = tcph->dest;

				/* Store tstamp to detect the reinjected SYN */
				ts = ktime_get_real_fast_ns();
				skb->tstamp = ts;

				con = init_con(syn, skb, hash_id, ts, 0);
				if (!con) {
					pep_err("Failed to init new pepcon");
					kfree(syn);
					return NF_DROP;
				}

				print_syn(syn->daddr, syn->dest);
				kfree(syn);
#ifndef CONFIG_PEPDNA_LOCAL_SENDER
				consume_skb(skb);
#endif
				return NF_STOLEN;
			} else {
				if (skb->tstamp != con->ts) {
					pep_dbg("Dropping duplicate SYN");
					return NF_DROP;
				}
			}
		}
	}
	return NF_ACCEPT;
}

#ifdef CONFIG_PEPDNA_MINIP
/**
 * pepdna_mip_recv_skb - handle incoming MINIP message from an interface
 * @skb: the received message
 * @dev: the net device that the packet was received on
 * @pt: the packet_type structure which was used to register this handler
 * @orig_dev: the original receive net device in case the device is a bond
 */
static int pepdna_mip_recv_skb(struct sk_buff *skb, struct net_device *dev,
			       struct packet_type *pt, struct net_device *orig_dev)
{
	if (!skb)
		return NET_RX_DROP;

	if (pepdna_mip_recv_packet(skb)) {
		pep_dbg("Dropping MIP skb");

		dev_kfree_skb_any(skb);
		return NET_RX_DROP;
	}

	return NET_RX_SUCCESS;
}
#endif

static const struct nf_hook_ops pepdna_inet_nf_ops[] = {
	{
		.hook		= pepdna_pre_hook,
		.pf		= NFPROTO_IPV4,
#ifndef CONFIG_PEPDNA_LOCAL_SENDER
		.hooknum	= NF_INET_PRE_ROUTING,
#else
		.hooknum	= NF_INET_LOCAL_OUT,
#endif
		.priority	= NF_PEPDNA_PRI,
	},
};

/*
 * Start TCP-TCP task
 * This function is called by pepdna_server_start() @'server.c'
 * --------------------------------------------------------------------------*/
static int pepdna_i2i_start(struct pepsrv *srv)
{
	int rc = pepdna_work_init(srv);
	if (rc < 0)
		return rc;

	INIT_WORK(&srv->accept_work, pepdna_acceptor_work);

	rc = pepdna_tcp_listen_init(srv);
	if (rc < 0) {
		pepdna_work_stop(srv);
		return rc;
	}

	nf_register_net_hooks(&init_net, pepdna_inet_nf_ops,
			      ARRAY_SIZE(pepdna_inet_nf_ops));
	return 0;
}

#ifdef CONFIG_PEPDNA_RINA
/*
 * Start RINA-TCP task
 * This function is called by pepdna_server_start() @'server.c'
 * --------------------------------------------------------------------------*/
static int pepdna_r2i_start(struct pepsrv *srv)
{
	int rc = pepdna_netlink_init();
	if (rc < 0) {
		pep_err("Failed to initialize Netlink socket");
		return rc;
	}

	rc = pepdna_work_init(srv);
	if (rc < 0) {
		pepdna_netlink_stop();
		return rc;
	}

	return 0;
}

/*
 * Start TCP-RINA task
 * This function is called by pepdna_server_start() @'server.c'
 * ------------------------------------------------------------------------- */
static int pepdna_i2r_start(struct pepsrv *srv)
{
	int rc = 0;

	INIT_WORK(&srv->accept_work, pepdna_acceptor_work);

	rc = pepdna_netlink_init();
	if (rc < 0) {
		pep_err("Couldn't init Netlink socket");
		return rc;
	}

	rc = pepdna_work_init(srv);
	if (rc < 0) {
		pepdna_netlink_stop();
		return rc;
	}

	rc = pepdna_tcp_listen_init(srv);
	if (rc < 0) {
		pepdna_netlink_stop();
		pepdna_work_stop(srv);
		return rc;
	}

	nf_register_net_hooks(&init_net, pepdna_inet_nf_ops,
			      ARRAY_SIZE(pepdna_inet_nf_ops));
	return 0;
}

/*
 * Start RINA-RINA task
 * This function is called by pepdna_server_start() @'server.c'
 * --------------------------------------------------------------------------*/
static int pepdna_r2r_start(struct pepsrv *srv)
{
	/* Not implemented yet */

	return 0;
}
#endif

#ifdef CONFIG_PEPDNA_MINIP
/*
 * Start MINIP-TCP task
 * This function is called by pepdna_server_start() @'server.c'
 * --------------------------------------------------------------------------*/
static int pepdna_m2i_start(struct pepsrv *srv)
{
	struct net_device *dev;

	int rc = pepdna_work_init(srv);
	if (rc < 0) {
		return rc;
	}

	/* Check if dev is not NULL */
	dev = dev_get_by_name(&init_net, ifname);
	if (!dev) {
		pr_err("Failed to get net_device for interface: %s", ifname);
		return -ENODEV;
	}

	minip.type = htons(ETH_P_MINIP);
	minip.dev = dev;
	minip.func = pepdna_mip_recv_skb;
	dev_add_pack (&minip);

	dev_put(dev);

	return 0;
}

/*
 * Start TCP-MINIP task
 * This function is called by pepdna_server_start() @'server.c'
 * ------------------------------------------------------------------------- */
static int pepdna_i2m_start(struct pepsrv *srv)
{
	struct net_device *dev;

	int rc = pepdna_work_init(srv);
	if (rc < 0)
		return rc;

	INIT_WORK(&srv->accept_work, pepdna_acceptor_work);

	rc = pepdna_tcp_listen_init(srv);
	if (rc < 0) {
		pepdna_work_stop(srv);
		return rc;
	}

	nf_register_net_hooks(&init_net, pepdna_inet_nf_ops,
			      ARRAY_SIZE(pepdna_inet_nf_ops));

	/* Check if dev is not NULL */
	dev = dev_get_by_name(&init_net, ifname);
	if (!dev) {
		pr_err("Failed to get net_device for interface: %s", ifname);
		return -ENODEV;
	}

	/*
	 * setup the receive function from driver on the ethertype for
	 * the given device
	 */
	minip.type = htons(ETH_P_MINIP);
	minip.dev = dev;
	minip.func = pepdna_mip_recv_skb;
	dev_add_pack(&minip);

	dev_put(dev);

	return 0;
}
#endif

#ifdef CONFIG_PEPDNA_CCN
/*
 * Start TCP-CCN task
 * This function is called by pepdna_server_start() @'server.c'
 * --------------------------------------------------------------------------*/
static int pepdna_i2c_start(struct pepsrv *srv)
{
	int rc = 0;

	INIT_WORK(&srv->accept_work, pepdna_acceptor_work);

	rc = pepdna_work_init(srv);
	if (rc < 0)
		return rc;

	rc = pepdna_tcp_listen_init(srv);
	if (rc < 0) {
		pepdna_work_stop(srv);
		return rc;
	}

	nf_register_net_hooks(&init_net, pepdna_inet_nf_ops,
			      ARRAY_SIZE(pepdna_inet_nf_ops));
	return 0;
}

/*
 * Start CCN-TCP task
 * This function is called by pepdna_server_start() @'server.c'
 * --------------------------------------------------------------------------*/
static int pepdna_c2i_start(struct pepsrv *srv)
{
	/* TODO: Not implemented yet */

	return 0;
}

/*
 * Start CCN-CCN task
 * This function is called by pepdna_server_start() @'server.c'
 * --------------------------------------------------------------------------*/
static int pepdna_c2c_start(struct pepsrv *srv)
{
	/* TODO: Not implemented yet */

	return 0;
}
#endif

static void init_pepdna_server(struct pepsrv *srv)
{
	pepdna_srv = srv;
	srv->mode  = mode;
	srv->port  = port;

#ifdef CONFIG_PEPDNA_MINIP
	if (mac) {
		mac_pton(mac, srv->to_mac);
                if (!is_valid_ether_addr(srv->to_mac) &&
                    !is_broadcast_ether_addr(srv->to_mac)) {
			pep_err("invalid MAC address of the peer pepdna");
		}
                else {
			pep_dbg("MAC address of the peer pepdna %s", mac);
		}
        }
#endif
	srv->listener  = NULL;
	srv->in2out_wq = NULL;
	srv->out2in_wq = NULL;

	atomic_set(&srv->conns, 0);
	hash_init(srv->htable);
}

/**
 * pepdna_server_start - Initialize and start the PEPDNA server
 *
 * Allocates server structure, initializes it, and starts the appropriate
 * server type based on the configured mode.
 *
 * Return: 0 on success, negative error code on failure
 */
int pepdna_server_start(void)
{
	struct pepsrv *srv;
	int rc;

	/* Allocate server structure */
	srv = kzalloc(sizeof(*srv), GFP_KERNEL);
	if (!srv) {
		pep_err("Failed to allocate memory for server");
		return -ENOMEM;
	}

	/* Initialize the server structure */
	init_pepdna_server(srv);

	/* Start the server based on configured mode */
	switch (srv->mode) {
	case TCP2TCP:
		rc = pepdna_i2i_start(srv);
		if (rc < 0) {
			pep_err("Failed to start TCP2TCP server, error %d", rc);
			goto err_start;
		}
		break;

#ifdef CONFIG_PEPDNA_RINA
	case TCP2RINA:
		rc = pepdna_i2r_start(srv);
		if (rc < 0) {
			pep_err("Failed to start TCP2RINA server, error %d", rc);
			goto err_start;
		}
		break;

	case RINA2TCP:
		rc = pepdna_r2i_start(srv);
		if (rc < 0) {
			pep_err("Failed to start RINA2TCP server, error %d", rc);
			goto err_start;
		}
		break;

	case RINA2RINA:
		rc = pepdna_r2r_start(srv);
		if (rc < 0) {
			pep_err("Failed to start RINA2RINA server, error %d", rc);
			goto err_start;
		}
		break;
#endif /* CONFIG_PEPDNA_RINA */

#ifdef CONFIG_PEPDNA_CCN
	case TCP2CCN:
		rc = pepdna_i2c_start(srv);
		if (rc < 0) {
			pep_err("Failed to start TCP2CCN server, error %d", rc);
			goto err_start;
		}
		break;

	case CCN2TCP:
		rc = pepdna_c2i_start(srv);
		if (rc < 0) {
			pep_err("Failed to start CCN2TCP server, error %d", rc);
			goto err_start;
		}
		break;

	case CCN2CCN:
		rc = pepdna_c2c_start(srv);
		if (rc < 0) {
			pep_err("Failed to start CCN2CCN server, error %d", rc);
			goto err_start;
		}
		break;
#endif /* CONFIG_PEPDNA_CCN */

#ifdef CONFIG_PEPDNA_MINIP
	case TCP2MINIP:
		rc = pepdna_i2m_start(srv);
		if (rc < 0) {
			pep_err("Failed to start TCP2MINIP server, error %d", rc);
			goto err_start;
		}
		break;

	case MINIP2TCP:
		rc = pepdna_m2i_start(srv);
		if (rc < 0) {
			pep_err("Failed to start MINIP2TCP server, error %d", rc);
			goto err_start;
		}
		break;
#endif /* CONFIG_PEPDNA_MINIP */

	default:
		pep_err("Unknown PEPDNA mode %d", srv->mode);
		rc = -EINVAL;
		goto err_start;
	}

	return 0;

err_start:
	kfree(srv);
	return rc;
}

/*
 * PEPDNA server stop
 * This function is called by module_exit() @'core.c'
 * ------------------------------------------------------------------------- */

void pepdna_server_stop(void)
{
	struct socket *lsock = pepdna_srv->listener;
	struct pepcon *con = NULL;
	struct hlist_node *tmp;
	int i, active_conns = 0;

	/* 1. First, unregister NF_HOOK to stop processing new SYNs */
	/* Only TCP2X modes have a Netfilter hook */
	if (pepdna_srv->mode < 4) {
		nf_unregister_net_hooks(&init_net, pepdna_inet_nf_ops,
					ARRAY_SIZE(pepdna_inet_nf_ops));
        }

	/* 2. Check for connections which are still alive and force cleanup */
	if (atomic_read(&pepdna_srv->conns)) {
		pep_info("Cleaning up %d active connections",
			 atomic_read(&pepdna_srv->conns));

		// Iterate through all hash buckets
		hash_for_each_safe(pepdna_srv->htable, i, tmp, con, hlist) {
		if (!con)
			continue;
		active_conns++;
#ifdef CONFIG_PEPDNA_MINIP
		// Cancel any pending timers
		if (timer_pending(&con->rto_timer) ||
		    timer_pending(&con->zombie_timer)) {
			pep_dbg("Deleting pending timers for conn id %u", con->id);
			timer_delete_sync(&con->rto_timer);
			timer_delete_sync(&con->zombie_timer);
		}
#endif
		// Close the connection first (clear callbacks, etc.)
		close_con(con);

		/* Check for non-NULL con->rx_buff */
		if (con->rx_buff) {
			pep_dbg("Freeing rx_buff for conn id %u", con->id);
			kfree(con->rx_buff);
			con->rx_buff = NULL;
		}

		// Force connection into a final cleanup state
		switch (pepdna_srv->mode) {
#ifdef CONFIG_PEPDNA_MINIP
		case TCP2MINIP:
		case MINIP2TCP:
			// Force to ZOMBIE and free resources
			WRITE_ONCE(con->state, ZOMBIE);

			/* Purge MIP rx list */
			spin_lock_bh(&con->mip_rx_list.lock);
			__skb_queue_purge(&con->mip_rx_list);
			spin_unlock_bh(&con->mip_rx_list.lock);

			/* Purge MIP rtx list */
			spin_lock_bh(&con->mip_rtx_list.lock);
			__skb_queue_purge(&con->mip_rtx_list);
			spin_unlock_bh(&con->mip_rtx_list.lock);

			break;
#endif
#ifdef CONFIG_PEPDNA_RINA
		case TCP2RINA:
		case RINA2TCP:
			// Cancel any pending timers
			if (timer_pending(&con->zombie_timer)) {
				pep_dbg("Deleting pending zombie timer for conn id %u", con->id);
				timer_delete_sync(&con->zombie_timer);
			}
			break;
#endif
		default:
			// TCP2TCP or other protocol cleanup
			// Cancel any pending timers
			if (timer_pending(&con->zombie_timer)) {
				pep_dbg("Deleting pending zombie timer for conn id %u", con->id);
				timer_delete_sync(&con->zombie_timer);
			}
			break;
		}
		// Now forcibly release our reference
		pep_warn("Shutting down conn id %u", con->id);
		put_con(con);
		}
		pep_info("Cleaned up %d connections", active_conns);

		// Allow a short time for any queued work to complete
		schedule_timeout_uninterruptible(HZ/10);
	}

	/* 3. Release main listening socket and Netlink socket */
	pepdna_netlink_stop();
	pepdna_srv->listener = NULL;
	pepdna_tcp_listen_stop(lsock, &pepdna_srv->accept_work);

	/* 4. Flush and Destroy all works */
	pepdna_work_stop(pepdna_srv);

#ifdef CONFIG_PEPDNA_MINIP
	/* Remove the MINIP packet hook */
	dev_remove_pack(&minip);

#endif
	/* 5. kfree PEPDNA server struct */
	kfree(pepdna_srv);
	pepdna_srv = NULL;
	pep_info("Au Revoir PEP-DNA!");
}
