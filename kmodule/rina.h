/*
 *  pep-dna/kmodule/rina.h: Header file for PEP-DNA RINA support
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

#ifndef _PEPDNA_RINA_H
#define _PEPDNA_RINA_H

#ifdef CONFIG_PEPDNA_RINA
#include "kfa.h"	 /* included for struct ipcp_flow */
#include "kipcm.h"	 /* default_kipcm */
#include "rds/rfifo.h"	 /* rfifo_is_empty */
#include "rds/rmem.h"	 /* rkzalloc */

struct pepcon;
struct nl_msg;

/* timeout for RINA flow poller in usesc */
#define FLOW_POLL_TIMEOUT 1000

#define IRQ_BARRIER							\
	do {								\
		if (in_interrupt()) {					\
			BUG();						\
		}							\
	} while (0)

/**
 * RINA_ZOMBIE_TIMEOUT - Wait 10s before deallocating the flow to ensure that
 * all packets have been delivered
 */
#define RINA_ZOMBIE_TIMEOUT 10000u

/* Exported Symbols from IRATI kernel modules */
extern int kfa_flow_du_read(struct kfa *, int32_t, struct du **, size_t, bool);
extern struct ipcp_instance *kipcm_find_ipcp(struct kipcm *, uint16_t);
extern struct ipcp_flow *kfa_flow_find_by_pid(struct kfa *, int32_t);
extern unsigned char *du_buffer(const struct du *);
extern struct kfa *kipcm_kfa(struct kipcm *);
extern void * rkzalloc(size_t, gfp_t);
extern bool rfifo_is_empty(struct rfifo *);
extern bool is_du_ok(const struct du *);
extern struct du *du_create(size_t);
extern struct kipcm *default_kipcm;

bool flow_is_ready(struct pepcon *);
void pepdna_rina_flow_alloc(struct work_struct *);
void pepdna_con_i2r_work(struct work_struct *);
void pepdna_con_r2i_work(struct work_struct *);
void nl_i2r_callback(struct nl_msg *);
void nl_r2i_callback(struct nl_msg *);
void rina_zombie_timeout(struct timer_list *);
#endif

#endif /* _PEPDNA_RINA_H */
