/*
 *  pep-dna/pepdna/kmodule/tcp.h: Header file for PEP-DNA TCP support
 *
 *  Copyright (C) 2020  Kristjon Ciko <kristjoc@ifi.uio.no>
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

#ifndef _PEPDNA_TCP_H
#define _PEPDNA_TCP_H

#include "connection.h"
#include "tcp_utils.h"

#define PEPDNA_SOCK_MARK 333

/**
 * TCP_ZOMBIE_TIMEOUT - Wait 10s after a connection is closed, where
 * the system waits for a period to ensure that all packets have been
 * properly acknowledged
 */
#define TCP_ZOMBIE_TIMEOUT 10000u

/* tcp_listen.c */
void pepdna_tcp_listen_stop(struct socket *, struct work_struct *);
int  pepdna_tcp_listen_init(struct pepdna_server *);
void pepdna_acceptor_work(struct work_struct *work);

/* tcp_connect.c */
void pepdna_tcp_connect(struct work_struct *);

/* tcp.c */
void pepdna_tcp_in2out_work(struct work_struct *);
void pepdna_tcp_out2in_work(struct work_struct *);
int  pepdna_con_i2i_fwd(struct pepdna_con *,
			struct socket *,
			struct socket *);
void tcp_con_timeout(struct timer_list *);

#endif /* _PEPDNA_TCP_H */
