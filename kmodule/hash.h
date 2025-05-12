/*
 *  pep-dna/pepdna/kmodule/hash.h: Header file for PEP-DNA hash functions
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

#ifndef _PEPDNA_HASH_H
#define _PEPDNA_HASH_H

#include <linux/types.h>        /* types __u32, _be32, etc. */

#define pepdna_hash_seed 1315423911

__u32 pepdna_hash32_rjenkins1_2(__be32, __be16);

#endif /* _PEPDNA_HASH_H */
