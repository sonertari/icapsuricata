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

 #include <stdio.h>

typedef struct {
    char *buffer;
    size_t capacity;        // Total size of the allocated ring array
    size_t write_ptr;       // Where new data from c-icap goes
    size_t read_client_ptr; // Tracking index for data sent to client
    size_t read_suri_ptr;   // Tracking index for data injected to Suricata
} dual_ring_buf_t;

dual_ring_buf_t *dual_ring_buf_create(size_t capacity);
void dual_ring_buf_destroy(dual_ring_buf_t *rb);
void dual_ring_buf_clear(dual_ring_buf_t *rb);

size_t dual_ring_buf_write_available(dual_ring_buf_t *rb);
size_t dual_ring_buf_write(dual_ring_buf_t *rb, const char *src, size_t len);

size_t dual_ring_buf_client_read_available(dual_ring_buf_t *rb);
size_t dual_ring_buf_client_read(dual_ring_buf_t *rb, char *dst, size_t max_len);

size_t dual_ring_buf_suri_read_available(dual_ring_buf_t *rb);
size_t dual_ring_buf_suri_read(dual_ring_buf_t *rb, char *dst, size_t max_len);
