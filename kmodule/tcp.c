/*
 *  pep-dna/pepdna/kmodule/tcp.c: PEP-DNA TCP support
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
#include "server.h"
#include "tcp.h"
#include "tcp_utils.h"

void tcp_zombie_timeout(struct timer_list *t)
{
	struct pepcon *con = from_timer(con, t, zombie_timer);

	put_con(con);
}


/*
 * Forward data from one TCP socket to another
 * ------------------------------------------------------------------------- */
int pepdna_con_i2i_fwd(struct pepcon *con, struct socket *from,struct socket *to)
{
	struct msghdr msg;
	struct kvec vec;
	int rx, tx;

	vec.iov_base = con->rx_buff;
	vec.iov_len  = MAX_BUF_SIZE;
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

/*
 * TCP2TCP scenario
 * Forwarding from Right to Left INTERNET domain
 * ------------------------------------------------------------------------- */
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

/*
 * TCP2TCP scenario
 * Forwarding from Left to Right INTERNET domain
 * ------------------------------------------------------------------------- */
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
