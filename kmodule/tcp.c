/*
 *  pep-dna/pepdna/kmodule/tcp.c: PEP-DNA TCP support
 *
 *  Copyright (C) 2026  Kristjon Ciko <kristjoc@ifi.uio.no>
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
#include "server.h"
#include "tcp.h"
#include "tcp_utils.h"

/**
 * tcp_zombie_timeout() - Timer callback to clean up a zombie connection.
 * @t: Timer structure embedded in the pepcon context.
 *
 * Drops the connection reference, allowing it to be freed.
 */
void tcp_zombie_timeout(struct timer_list *t)
{
	struct pepcon *con = from_timer(con, t, zombie_timer);

	put_con(con);
}

/**
 * pepdna_con_i2i_fwd() - Forward data from one TCP socket to another.
 * @con:  Connection instance
 * @from: Source socket to read data from.
 * @to:   Destination socket to write data to.
 *
 * Performs a non-blocking read from the source socket and writes
 * the received data to the destination socket.
 *
 * Return: The number of bytes received on success, 0 on orderly
 * shutdown, or a negative error code on failure (e.g., -EAGAIN).
 */
int pepdna_con_i2i_fwd(struct pepcon *con, struct socket *from, struct socket *to)
{
	struct msghdr msg;
	struct kvec vec;
	int rx, tx;

	vec.iov_base = con->rx_buff;
	vec.iov_len  = PEPDNA_RXBUF_SIZE;
	// Initialize msg structure
	msg.msg_flags = MSG_DONTWAIT;

	rx = kernel_recvmsg(from, &msg, &vec, 1, vec.iov_len, MSG_DONTWAIT);
	if (likely(rx > 0)) {
		tx = pepdna_sock_write(to, con->rx_buff, rx);
		if (tx < 0) {
			pep_err("Failed to forward %d bytes to TCP socket", rx);
			return tx;
		}
	}
	return rx;
}

/**
 * pepdna_tcp_out2in_work() - Forward TCP traffic from right to left domain.
 * @work: The work structure embedded in the pepcon context.
 *
 * Workqueue handler that continuously forwards data from the right
 * socket to the left socket. Yields on -EAGAIN and closes the
 * connection on terminal errors.
 */
void pepdna_tcp_out2in_work(struct work_struct *work)
{
	struct pepcon *con = container_of(work, struct pepcon, out2in_work);
	int rc = 0;

	while (rconnected(con)) {
		if ((rc = pepdna_con_i2i_fwd(con, con->rsock, con->lsock)) <= 0) {
			if (rc == -EAGAIN)
				break;
			close_con(con);
		}
	}
	put_con(con);
}

/**
 * pepdna_tcp_in2out_work() - Forward TCP traffic from left to right domain.
 * @work: The work structure embedded in the pepcon context.
 *
 * Workqueue handler that continuously forwards data from the left
 * socket to the right socket. Yields on -EAGAIN and closes the
 * connection on terminal errors.
 */
void pepdna_tcp_in2out_work(struct work_struct *work)
{
	struct pepcon *con = container_of(work, struct pepcon, in2out_work);
	int rc = 0;

	while (lconnected(con)) {
		if ((rc = pepdna_con_i2i_fwd(con, con->lsock, con->rsock)) <= 0) {
			if (rc == -EAGAIN)
				break;
			close_con(con);
		}
	}
	put_con(con);
}
