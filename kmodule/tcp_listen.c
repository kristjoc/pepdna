/*
 *  pep-dna/pepdna/kmodule/tcp_listen.c: PEP-DNA TCP listen()
 *
 *  Copyright (C) 2025	Kristjon Ciko <kristjoc@ifi.uio.no>
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

#include <linux/module.h>

static void pepdna_tcp_listen_data_ready(struct sock *);
static int pepdna_tcp_accept(struct pepsrv *);

/**
 * pepdna_tcp_listen_data_ready - Callback for data ready events on listening socket
 * @sk: Socket that received the data ready event
 *
 * This function is called when the listening socket has a connection ready
 * to be accepted. It processes the incoming connection and then calls the
 * original data_ready function that was saved during initialization.
 */
static void pepdna_tcp_listen_data_ready(struct sock *sk)
{
	void (*original_callback)(struct sock *sk);

	pep_dbg("TCP listen data ready on socket %p", sk);

	/* Retrieve the original callback under lock */
	read_lock_bh(&sk->sk_callback_lock);
	original_callback = sk->sk_user_data;
	if (!original_callback) { 
		/* Check for teardown race condition */
		pep_dbg("Socket callback data is NULL, possible teardown");
		original_callback = sk->sk_data_ready;
		goto unlock;
	}

	/* Process incoming connection if this is a listening socket */
	if (sk->sk_state == TCP_LISTEN)
		/* Handle the connection directly */
		schedule_work(&pepdna_srv->accept_work);
unlock:
	read_unlock_bh(&sk->sk_callback_lock);

	/* Call the original callback function */
	if (original_callback)
		original_callback(sk);
}

/**
 * pepdna_tcp_listen_init - Initialize TCP listening socket for PEPDNA server
 * @srv: Server structure to initialize
 *
 * Creates and configures a TCP socket for listening, binds it to the specified
 * port, and sets up the listening queue.
 *
 * Return: 0 on success, negative error code on failure
 */
int pepdna_tcp_listen_init(struct pepsrv *srv)
{
	struct socket *sock;
	struct sock *sk;
	struct sockaddr_in saddr;
	int addr_len;
	int rc;

	/* Create socket */
	rc = sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP,
			      &sock);
	if (rc < 0) {
		pep_err("Failed to create socket, error %d", rc);
		return rc;
	}

	srv->listener = sock;
	sk = sock->sk;

	/* Tune TCP socket parameters */
	sk->sk_reuse = SK_CAN_REUSE;
	pepdna_set_bufsize(sock);
	pepdna_tcp_nonagle(sock);
	pepdna_tcp_nodelayedack(sock);
	pepdna_ip_transparent(sock);

	/* Register callback for incoming connections */
	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_user_data  = sk->sk_data_ready;
	sk->sk_data_ready = pepdna_tcp_listen_data_ready;
	write_unlock_bh(&sk->sk_callback_lock);

	/* Prepare bind address */
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family      = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port        = htons(srv->port);
	addr_len              = sizeof(saddr);

	/* Bind socket to address */
	rc = kernel_bind(sock, (struct sockaddr *)&saddr, addr_len);
	if (rc < 0) {
		pep_err("Failed to bind to port %d, error %d", srv->port, rc);
		goto err_bind;
	}
	pep_dbg("Listener bound to port %d", srv->port);

	/* Start listening, pending connections queue size=1024 */
	rc = kernel_listen(sock, 1024);
	if (rc < 0) {
		pep_err("Failed to listen on socket, error %d", rc);
		goto err_listen;
	}
	pep_dbg("Listening for incoming TCP connection requests");

	return 0;

err_listen:
err_bind:
	sock_release(sock);
	return rc;
}

/**
 * pepdna_tcp_accept - Accept incoming TCP connections for PEPDNA server
 * @srv: Server structure handling the connections
 *
 * Accepts pending TCP connections, identifies the client, and sets up
 * the necessary callbacks and data structures.
 *
 * Return: 0 on success, negative error code on failure
 */
static int pepdna_tcp_accept(struct pepsrv *srv)
{
	struct socket *sock, *asock;
	struct sock *lsk, *rsk;
	struct pepcon *con;
	u32 id;
	int rc;

	if (!srv || !srv->listener) {
		pep_err("Invalid server or listener socket");
		return -EINVAL;
	}

	sock = srv->listener;

	/* Accept loop - process all pending connections */
	while (1) {
		/* Accept a new connection */
		rc = kernel_accept(sock, &asock, O_NONBLOCK);
		if (rc < 0) {
			/* No more pending connections or error */
			if (rc == -EAGAIN || rc == -EWOULDBLOCK)
				return 0;
			pep_dbg("No more connections or accept error: %d", rc);
			return rc;
		}

		/* Identify the client */
		id = pepdna_get_id_from_sock(asock);
		con = find_con(id);
		if (!con) {
			pep_err("conn id %u not found", id);
			sock_release(asock);
			asock = NULL;
			return -ENOENT;
		}

		pep_dbg("Accepted new conn id %u", id);

		/* Set up the local socket and register callbacks */
		con->lsock = asock;
		lsk = asock->sk;

		write_lock_bh(&lsk->sk_callback_lock);
		lsk->sk_data_ready = pepdna_in2out_data_ready;
		lsk->sk_user_data = con;
		WRITE_ONCE(con->lflag, true);
		WRITE_ONCE(con->rflag, true);
		write_unlock_bh(&lsk->sk_callback_lock);

		/* FIXME Since this is intended to exist for the
                   entire duration of the connection, it is better ti
                   use struct task_struct */
		if (srv->mode == TCP2RINA) {
			/* Queue work for RINA-to-Internet direction if needed */

			get_con(con);
			if (!queue_work(srv->out2in_wq, &con->out2in_work)) {
				pep_err("out2in_work already in queue for conn %u", id);
				put_con(con);
				return -EBUSY;
			}
		}

		/* Wake up inbound and outbound sockets */
		lsk->sk_data_ready(lsk);

		if (con->rsock) {
			rsk = con->rsock->sk;
			rsk->sk_data_ready(rsk);
		}
	}

	/* Control should never reach here due to the infinite loop */
	return 0;
}

/**
 * pepdna_acceptor_work - Work queue handler for accepting connections
 * @work: Work structure containing the server context
 *
 * This function is scheduled when the listening socket has connection(s)
 * ready to be accepted. It extracts the server context and calls the
 * TCP accept handler function.
 */
void pepdna_acceptor_work(struct work_struct *work)
{
	struct pepsrv *srv;
	int rc;

	/* Get server context from work structure */
	srv = container_of(work, struct pepsrv, accept_work);
	if (!srv) {
		pep_err("Invalid server context in acceptor work");
		return;
	}

	/* Process pending TCP connections */
	rc = pepdna_tcp_accept(srv);
	if (rc >= 0) {
		pep_dbg("TCP accept processed successfully, rc=%d", rc);
	} else {
		pep_dbg("TCP accept failed with error %d", rc);

		/* Only log detailed errors for significant issues */
		if (rc != -EAGAIN && rc != -EWOULDBLOCK)
			pep_err("Accept processing error: %d", rc);
	}
}

/**
 * pepdna_tcp_listen_stop - Stop the TCP listening socket
 * @sock: Listening socket to stop
 * @acceptor: Work structure for the accept handler
 *
 * Restores the original data_ready callback, ensures all pending
 * accept work has completed, and releases the socket.
 */
void pepdna_tcp_listen_stop(struct socket *sock, struct work_struct *acceptor)
{
	struct sock *sk;

	/* Safety check - if no socket or no server, nothing to do */
	if (!sock || !pepdna_srv)
		return;

	pep_dbg("Stopping PEPDNA TCP listener");

	sk = sock->sk;
	if (!sk) {
		pep_err("Invalid socket state in listen_stop");
		return;
	}

	/* Serialize with and prevent further callbacks */
	lock_sock(sk);
	write_lock_bh(&sk->sk_callback_lock);

	/* Restore original data_ready callback */
	if (sk->sk_user_data) {
		sk->sk_data_ready = sk->sk_user_data;
		sk->sk_user_data = NULL;
		pep_dbg("Restored original socket callbacks");
	}

	write_unlock_bh(&sk->sk_callback_lock);
	release_sock(sk);

	/* 
	 * Wait for any pending accept work to complete
	 * No need to flush a workqueue since we're using the global one
	 */
	if (acceptor) {
		pep_dbg("Flushing accept work");
		flush_work(acceptor);
	}

	/* Release the socket */
	pep_dbg("Releasing TCP listener socket");
	sock_release(sock);
}
