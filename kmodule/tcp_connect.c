/*
 *  pep-dna/kmodule/tcp_connet.c: PEP-DNA TCP connect()
 *
 *  Copyright (C) 2025  Kristjon Ciko <kristjoc@ifi.uio.no>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "connection.h"
#include "tcp.h"
#include "core.h"
#include "netlink.h"
#include "tcp_utils.h"

#ifdef CONFIG_PEPDNA_RINA
#include "rina.h"
#endif

#ifdef CONFIG_PEPDNA_MINIP
#include "mip.h"
#endif

#ifdef CONFIG_PEPDNA_LOCAL_SENDER
#include <net/ip.h>
#endif

/**
 * pepdna_tcp_connect - Establish TCP connection for PEPDNA
 * @work: Work structure containing the connection context
 *
 * Creates a socket, binds to source address, connects to destination,
 * sets socket options, and registers callbacks based on the PEPDNA mode.
 * This function is called from a workqueue.
 */
void pepdna_tcp_connect(struct work_struct *work)
{
	struct sockaddr_in saddr, daddr;
	struct socket *sock = NULL;
	struct sock *sk = NULL;
	struct pepcon *con;
	char from[16], to[16];
	int rc = 0;

	/* Get connection context from work structure */
	con = container_of(work, struct pepcon, connect_work);
	if (!con) {
		pep_err("Invalid connection in connect_work");
		return;
	}

	/* Create socket */
	rc = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (rc < 0) {
		pep_err("Failed to create socket, error %d", rc);
		goto err;
	}

	/* Prepare source and destination addresses */
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family      = AF_INET;
	saddr.sin_addr.s_addr = con->syn.saddr;
	saddr.sin_port        = con->syn.source;

	memset(&daddr, 0, sizeof(daddr));
	daddr.sin_family      = AF_INET;
#ifdef CONFIG_PEPDNA_LOCAL_RECEIVER
	daddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#else
	daddr.sin_addr.s_addr = con->syn.daddr;
#endif
	daddr.sin_port        = con->syn.dest;

	/* Configure TCP socket parameters */
	sock->sk->sk_reuse = SK_CAN_REUSE;
	pepdna_set_bufsize(sock);
	pepdna_tcp_nonagle(sock);
	pepdna_tcp_nodelayedack(sock);

	/* Set socket options based on configuration */
#ifndef CONFIG_PEPDNA_LOCAL_SENDER
	/* Set IP_TRANSPARENT to allow binding to non-local addresses */
	pepdna_ip_transparent(sock);
#endif

#if defined(CONFIG_PEPDNA_LOCAL_SENDER) || defined(CONFIG_PEPDNA_LOCAL_RECEIVER)
	/* Mark socket for local routing */
	pepdna_set_mark(sock, PEPDNA_SOCK_MARK);
#endif

#ifndef CONFIG_PEPDNA_LOCAL_SENDER
	/* Bind to source address to spoof client */
	rc = kernel_bind(sock, (struct sockaddr *)&saddr, sizeof(saddr));
	if (rc < 0) {
		pep_err("Failed to bind to source address, error %d", rc);
		sock_release(sock);
		goto err;
	}
#endif

	/* Convert addresses to strings for logging*/
	pepdna_inet_ntoa(from, sizeof(from), &saddr.sin_addr);
	pepdna_inet_ntoa(to,   sizeof(to),   &daddr.sin_addr);

	/* Connect to destination */
	rc = kernel_connect(sock, (struct sockaddr *)&daddr, sizeof(daddr), 0);
	if (rc < 0 && rc != -EINPROGRESS) {
		pep_err("Failed to connect to %s:%d, error %d", to,
			ntohs(daddr.sin_port), rc);
		if (sock) {
			kernel_sock_shutdown(sock, SHUT_RDWR);
			sock_release(sock);
		}

		/* Ask userspace fallocator to destroy the pending flow */
		pepdna_nl_sendmsg(0, 0, 0, 0, con->id,
				  atomic_read(&con->port_id),
				  PEPDNA_NL_MSG_DEALLOC);

		goto err;
	}

	pep_info("New session established <%s:%d - %s:%d>", from,
		 ntohs(saddr.sin_port), to, ntohs(daddr.sin_port));

	/* Handle different connection modes */
	if (con->srv->mode == TCP2TCP) {
		/* Register callbacks for outbound socket */
		con->rsock = sock;
		sk = sock->sk;
		write_lock_bh(&sk->sk_callback_lock);
		sk->sk_data_ready = pepdna_out2in_data_ready;
		sk->sk_user_data  = con;
		write_unlock_bh(&sk->sk_callback_lock);

		/* Reinject SYN packet to establish left TCP connection */
		pep_dbg("Reinjecting initial SYN packet to the stack");
#ifndef CONFIG_PEPDNA_LOCAL_SENDER
		netif_receive_skb(con->skb);
#else
		ip_local_out(sock_net(con->srv->listener->sk),
			     con->srv->listener->sk,
			     con->skb);
#endif
		return;
	}

#ifdef CONFIG_PEPDNA_RINA
	if (con->srv->mode == RINA2TCP) {
		rc = pepdna_nl_sendmsg(con->syn.saddr, con->syn.source,
				       con->syn.daddr, con->syn.dest,
				       con->id, atomic_read(&con->port_id),
				       PEPDNA_NL_MSG_ALLOC);
		if (rc < 0) {
			pep_err("Failed to resume flow allocation, error %d", rc);
			sock_release(sock);
			goto err;
		}

		/* Register callbacks for left socket */
		con->lsock = sock;
		sk = sock->sk;
		write_lock_bh(&sk->sk_callback_lock);
		sk->sk_data_ready = pepdna_in2out_data_ready;
		sk->sk_user_data  = con;
		write_unlock_bh(&sk->sk_callback_lock);

		return;
	}
#endif

#ifdef CONFIG_PEPDNA_MINIP
	if (con->srv->mode == MINIP2TCP) {
		rc = pepdna_mip_send_response(con);
		if (rc < 0) {
			pep_err("Failed to send MIP_CON_RESP, error %d", rc);
			sock_release(sock);
			goto err;
		}

		/* Update conn state assuming that the RESPONSE will make it */
		WRITE_ONCE(con->state, ESTABLISHED);
		con->next_seq++;
		atomic_inc(&con->last_acked);
		atomic_inc(&con->dupACK);
		con->next_recv++;

		/* Register callbacks for inbound socket */
		con->lsock = sock;
		sk = sock->sk;
		write_lock_bh(&sk->sk_callback_lock);
		sk->sk_data_ready = pepdna_in2out_data_ready;
		sk->sk_user_data  = con;
		write_unlock_bh(&sk->sk_callback_lock);

		/* Activate both sides of the connection */
		WRITE_ONCE(con->lflag, true);
		WRITE_ONCE(con->rflag, true);

		/* Wake up inbound socket in case the server has data to send */
		con->lsock->sk->sk_data_ready(con->lsock->sk);

		return;
	}
#endif
err:
	/* Close connection and release the initial allocation reference */
	close_con(con);
}
