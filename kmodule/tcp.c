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

void tcp_con_timeout(struct timer_list *t)
{
	struct pepdna_con *con = from_timer(con, t, timer);

	pepdna_con_put(con);
}


/*
 * Forward data from one TCP socket to another
 * ------------------------------------------------------------------------- */
int pepdna_con_i2i_fwd(struct pepdna_con *con,
		       struct socket *from,
		       struct socket *to)
{
	struct msghdr msg = {0};
	struct kvec vec;
	int read = 0, sent = 0;

	vec.iov_base = con->rx_buff;
	vec.iov_len  = MAX_BUF_SIZE;
	// Initialize msg structure
	msg.msg_flags = MSG_DONTWAIT;

	read = kernel_recvmsg(from, &msg, &vec, 1, vec.iov_len, MSG_DONTWAIT);
	if (likely(read > 0)) {
		sent = pepdna_sock_write(to, con->rx_buff, read);
		if (sent < 0) {
			pep_err("Failed to forward to TCP socket");
			return -1;
		}
	}

	return read;
}

/*
 * TCP2TCP scenario
 * Forwarding from Right to Left INTERNET domain
 * ------------------------------------------------------------------------- */
void pepdna_tcp_out2in_work(struct work_struct *work)
{
	struct pepdna_con *con = container_of(work, struct pepdna_con, out2in_work);
	int rc = 0;

	while (rconnected(con)) {
		if ((rc = pepdna_con_i2i_fwd(con, con->rsock, con->lsock)) <= 0) {
			if (rc == -EAGAIN)
				break;
			pepdna_con_close(con);
		}
	}
	pepdna_con_put(con);
}

/*
 * TCP2TCP scenario
 * Forwarding from Left to Right INTERNET domain
 * ------------------------------------------------------------------------- */
void pepdna_tcp_in2out_work(struct work_struct *work)
{
	struct pepdna_con *con = container_of(work, struct pepdna_con, in2out_work);
	int rc = 0;

	while (lconnected(con)) {
		if ((rc = pepdna_con_i2i_fwd(con, con->lsock, con->rsock)) <= 0) {
			if (rc == -EAGAIN)
				break;
			pepdna_con_close(con);
		}
	}
	pepdna_con_put(con);
}
