/*
 *  pep-dna/kmodule/utils.c: PEP-DNA related utilities
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

#include "core.h"
#include "connection.h"
#include "hash.h"
#include "tcp_utils.h"

#include <linux/kernel.h>   /* sprintf */
#include <linux/kthread.h>  /* kthread_should_stop */
#include <linux/string.h>   /* memset */
#include <linux/delay.h>    /* usleep_range */
#include <linux/slab.h>     /* kmalloc */
#include <linux/wait.h>     /* wait_event_interruptible */
#include <linux/net.h>      /* socket_wq */
#include <linux/version.h>  /* KERNEL_VERSION */
#include <linux/sched/signal.h> /* TASK_INTERRUPTIBLE */

#include <net/tcp.h>        /* TCP_NODELAY and TCP_QUICKACK */

static void pepdna_wait_to_send(struct sock *);
static bool pepdna_sock_writeable(struct sock *);


/*
 * Disable Delayed-ACK algorithm
 * ------------------------------------------------------------------------- */
void pepdna_tcp_nodelayedack(struct socket *sock)
{
	pep_dbg("Setting TCP_QUICKACK");

	tcp_sock_set_quickack(sock->sk, 1);
}

/*
 * Disable Nagle Algorithm
 * doing it this way avoids calling tcp_sk()
 * ------------------------------------------------------------------------- */
void pepdna_tcp_nonagle(struct socket *sock)
{
	pep_dbg("Disabling Nagle Algorithm");

	tcp_sock_set_nodelay(sock->sk);
}

/*
 * Because of certain restrictions in the IPv4 routing output code you'll have
 * to modify your application to allow it to send datagrams _from_ non-local IP
 * addresses. All you have to do is enable the (SOL_IP, IP_TRANSPARENT) socket
 * option before calling bind:
 * ------------------------------------------------------------------------- */
void pepdna_ip_transparent(struct socket *sock)
{
	sockptr_t optval;
	int rc = 0, val = 1;

	optval.kernel = (void *)&val;
	optval.is_kernel = true;

	rc = ip_setsockopt(sock->sk, SOL_IP, IP_TRANSPARENT, optval,
			   sizeof(optval));
	if (rc < 0) {
		pep_err("Failed to set IP_TRANSPARENT sockopt: %d\n", rc);
	}
}

void pepdna_set_mark(struct socket *sock, u32 val)
{
	sock_set_mark(sock->sk, val);

	pep_dbg("Marked socket with mark %u", val);
}

/*
 * Set BUF size
 * quoting tcp(7):
 *   On individual connections, the socket buffer size must be set prior to the
 *   listen(2) or connect(2) calls in order to have it take effect.
 *   This is the wrapper to do so.
 * ------------------------------------------------------------------------- */
void pepdna_set_bufsize(struct socket *sock)
{
	struct sock *sk = sock->sk;
	unsigned int snd, rcv;

	snd = sysctl_pepdna_sock_wmem[1];
	rcv = sysctl_pepdna_sock_rmem[1];

	if (snd) {
		sk->sk_userlocks |= SOCK_SNDBUF_LOCK;
		sk->sk_sndbuf = snd;
	}
	if (rcv) {
		sk->sk_userlocks |= SOCK_RCVBUF_LOCK;
		sk->sk_rcvbuf = rcv;
	}
}


/*
 * Check if socket send buffer has space
 * ------------------------------------------------------------------------- */
static bool pepdna_sock_writeable(struct sock *sk)
{
        if (sk_stream_is_writeable(sk)) {
		clear_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		return true;
	}

	return false;
}

/*
 * Wait for sock to become writeable
 * ------------------------------------------------------------------------- */
static void pepdna_wait_to_send(struct sock *sk)
{
	struct pepcon *con = sk->sk_user_data;
	struct socket_wq *wq = NULL;
	long timeo = usecs_to_jiffies(TCP_WAIT_TO_SEND);

	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	rcu_read_unlock();

	while(!pepdna_sock_writeable(sk)) {
		wait_event_interruptible_timeout(wq->wait,
						 pepdna_sock_writeable(sk),
						 timeo);
		if (!READ_ONCE(con->lflag) || !READ_ONCE(con->rflag))
			break;
	}
}

/*
 * Write buf of size_t len to TCP socket
 * Called by: pepdna_con_x2i_fwd()
 * ------------------------------------------------------------------------- */
int pepdna_sock_write(struct socket *sock, unsigned char *buff, size_t len)
{
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL };
	struct kvec vec;
	size_t left = len, sent = 0;
	int count = 0, rc = 0;

	while (left) {
		vec.iov_len = left;
		vec.iov_base = (unsigned char *)buff + sent;

		rc = kernel_sendmsg(sock, &msg, &vec, 1, left);
		pep_dbg("Wrote %d / %zu bytes to TCP socket", rc, len);

		/* Treat rc = 0 as a special case and try again */
		if (unlikely(!rc)) {
			if (++count < 2) {
				pep_dbg("Trying to send again after 0 return");
				continue;
			}
			return -EPIPE;
		}

		if (rc > 0) {
			sent += rc;
			left -= rc;
		} else {
			if (rc == -EAGAIN) {
				pep_dbg("TCP socket not writeable: -EAGAIN");
				pepdna_wait_to_send(sock->sk);
				/* cond_resched(); */
				continue;
			}
			return rc;
		}
	}
	return sent;
}

/*
 * Convert IP address from struct in_addr type to string
 * ------------------------------------------------------------------------- */
const char *inet_ntoa(struct in_addr *in)
{
	uint32_t int_ip = 0;
	char *str_ip    = NULL;

	str_ip = kzalloc(16 * sizeof(char), GFP_KERNEL);
	if (!str_ip)
		return NULL;

	int_ip = in->s_addr;

	sprintf(str_ip, "%d.%d.%d.%d", (int_ip) & 0xFF,
		(int_ip >> 8) & 0xFF,
		(int_ip >> 16) & 0xFF,
		(int_ip >> 24) & 0xFF);
	/* It is the duty of the caller to free the memory allocated by this
	 * function
	 */
	return str_ip;
}

/*
 * Convert string IP address to in_addr type
 * ------------------------------------------------------------------------- */
uint32_t inet_addr(char *ip)
{
	int a, b, c, d;
	char arr[4];
	u32 *tmp;

	sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d);
	arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;

	tmp = (u32*)arr;
	return *tmp;
}

void print_syn(__be32 daddr, __be16 dest)
{
	/* Convert the values to host byte order */
	u32 ip_daddr = ntohl(daddr);
	u16 tcp_dest = ntohs(dest);

	pep_dbg("Incoming SYN packet destined to %d.%d.%d.%d:%d",
		(ip_daddr >> 24) & 0xFF, (ip_daddr >> 16) & 0xFF,
		(ip_daddr >> 8) & 0xFF, ip_daddr & 0xFF, tcp_dest);
}

/*
 * Return the hash(saddr, source) of the connected socket
 * ------------------------------------------------------------------------- */
u32 identify_client(struct socket *sock)
{
	struct sockaddr_in *addr  = NULL;
	__be32 src_ip;
	__be16 sport;
	u32 id;
	int rc;

	addr = kzalloc(sizeof(struct sockaddr_in), GFP_KERNEL);
	if (!addr)
		return -ENOMEM;

	rc = sock->ops->getname(sock, (struct sockaddr *)addr, 2);
	if (rc < 0) {
		pep_err("Failed to identify socket, getname %d", rc);
		kfree(addr);
		addr = NULL;
		goto err;
	}

	src_ip   = addr->sin_addr.s_addr;
	sport = addr->sin_port;
	id  = pepdna_hash32_rjenkins1_2(src_ip, sport);

	kfree(addr);
	addr = NULL;

	return id;
err:
	if (sock) {
		sock_release(sock);
		sock = NULL;
	}

	return rc;
}
