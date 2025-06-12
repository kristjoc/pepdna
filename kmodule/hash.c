/*
 *  pep-dna/kmodule/hash.c: PEP-DNA hash function
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

#include "hash.h"
#include <linux/jhash.h>

/**
 * pepdna_hash32_rjenkins1_2 - Hash IP and port to 32-bit value
 * @src_ip:  Source IP address (network order)
 * @src_port: Source port (network order)
 *
 * Returns a 32-bit hash value for the given IP and port pair,
 * suitable for use as a hash table key.
 */
u32 pepdna_hash32_rjenkins1_2(__be32 src_ip, __be16 src_port)
{
	u32 a = be32_to_cpu(src_ip);
	u32 b = be16_to_cpu(src_port);

	return jhash_2words(a, b, pepdna_hash_seed);
}
