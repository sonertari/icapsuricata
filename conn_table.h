/*-
 * Suricata ICAP service
 *
 * Copyright (c) 2026, Soner Tari <sonertari@gmail.com>.
 * All rights reserved.
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#ifndef CONN_TABLE_H
#define CONN_TABLE_H

#include <stdint.h>

struct suri_conn_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint64_t stream_id;   /* int64_t for H2/H3 stream IDs */
    uint8_t  proto;       /* Enum/ID for tcp (0), https (1), http2 (2), http3 (3), http (4) */
};

void suri_conn_table_init(void);
void suri_conn_table_destroy(void);

int suri_conn_table_set(const struct suri_conn_key *, uint32_t, uint32_t, uint16_t);
int suri_conn_table_get(const struct suri_conn_key *, uint32_t *, uint32_t *, uint16_t *, int);
void suri_conn_table_delete(const struct suri_conn_key *);

#endif /* CONN_TABLE_H */
