/*
 *  pep-dna/kmodule/server.h: PEP-DNA server header
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

#ifndef _PEPDNA_SERVER_H
#define _PEPDNA_SERVER_H

#include <linux/workqueue.h>    /* work_struct, workqueue_struct, htable*/

#define MODULE_NAME      "pepdna"
#define NF_PEPDNA_PRI    -500
#define PEPDNA_HASH_BITS 9
#define ETH_ALEN	 6
#define MAX_SDU_SIZE     1448
#define MAX_BUF_SIZE     65535u

struct sock;
struct nl_msg;

enum server_mode {
	TCP2TCP = 0,
	TCP2RINA,
	TCP2CCN,
	TCP2MINIP,
	RINA2TCP,
	MINIP2TCP,
	CCN2TCP,
	RINA2RINA,
	CCN2CCN
};


/**
 * struct pepsrv - PEP-DNA server struct
 * @mode:        TCP2TCP | TCP2RINA | TCP2CCN | RINA2TCP | RINA2RINA ...
 * @in2out_wq:   in-bound to out-band workqueue
 * @out2in_wq:   out-band to in-band workqueue
 * @accept_work: TCP accept work item
 * @listener:    pepdna listener socket
 * @port:        pepdna TCP listener port
 * @htable:      Hash table for connections
 * @conns:	 counter for active connections
 */
struct pepsrv {
	enum server_mode mode;
	struct workqueue_struct *in2out_wq;
	struct workqueue_struct *out2in_wq;
	struct work_struct accept_work;
	struct socket *listener;
	int port;
#ifdef CONFIG_PEPDNA_MINIP
        u8 to_mac[ETH_ALEN];
#endif
	struct hlist_head htable[PEPDNA_HASH_BITS];
	atomic_t conns;
};

void pepdna_in2out_data_ready(struct sock *);
void pepdna_out2in_data_ready(struct sock *);
int  pepdna_server_start(void);
void pepdna_server_stop(void);

#endif /* _PEPDNA_SERVER_H */
