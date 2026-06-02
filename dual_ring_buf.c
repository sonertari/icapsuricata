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
#include <stdlib.h>
#include <string.h>

#include "dual_ring_buf.h"

#define MIN(x,y) ((x)>(y)?(y):(x))

/* ================= Ring buffer with dual readers ================= */

dual_ring_buf_t *dual_ring_buf_create(size_t capacity) {
    // Add +1 byte because a traditional circular buffer keeps one slot empty
    // to cleanly differentiate between an empty buffer and a full buffer.
    dual_ring_buf_t *rb = malloc(sizeof(dual_ring_buf_t));
    if (!rb) return NULL;

    rb->capacity = capacity + 1;
    rb->buffer = malloc(rb->capacity);
    if (!rb->buffer) {
        free(rb);
        return NULL;
    }
    dual_ring_buf_clear(rb);
    return rb;
}

void dual_ring_buf_destroy(dual_ring_buf_t *rb) {
    if (rb) {
        free(rb->buffer);
        free(rb);
    }
}

void dual_ring_buf_clear(dual_ring_buf_t *rb) {
    rb->write_ptr = 0;
    rb->read_client_ptr = 0;
    rb->read_suri_ptr = 0;
}

// Space reclamation is strictly dictated by whichever reader is lagging furthest behind.
size_t dual_ring_buf_write_available(dual_ring_buf_t *rb) {
    size_t trailing_edge = MIN(rb->read_client_ptr, rb->read_suri_ptr);
    if (rb->write_ptr >= trailing_edge) {
        return rb->capacity - (rb->write_ptr - trailing_edge) - 1;
    }
    return trailing_edge - rb->write_ptr - 1;
}

size_t dual_ring_buf_write(dual_ring_buf_t *rb, const char *src, size_t len) {
    size_t avail = dual_ring_buf_write_available(rb);
    if (len > avail) len = avail; // Clip to what safely fits
    if (len == 0) return 0;

    // Linear space from write pointer to physical end of the array
    size_t first_chunk = MIN(len, rb->capacity - rb->write_ptr);
    memcpy(rb->buffer + rb->write_ptr, src, first_chunk);

    // Remaining chunk wraps around to index 0
    if (len > first_chunk) {
        memcpy(rb->buffer, src + first_chunk, len - first_chunk);
    }

    rb->write_ptr = (rb->write_ptr + len) % rb->capacity;
    return len;
}

/* ==================== CLIENT READER INTERFACE ==================== */

size_t dual_ring_buf_client_read_available(dual_ring_buf_t *rb) {
    if (rb->write_ptr >= rb->read_client_ptr) {
        return rb->write_ptr - rb->read_client_ptr;
    }
    return rb->capacity - (rb->read_client_ptr - rb->write_ptr);
}

size_t dual_ring_buf_client_read(dual_ring_buf_t *rb, char *dst, size_t max_len) {
    size_t avail = dual_ring_buf_client_read_available(rb);
    if (max_len > avail) max_len = avail;
    if (max_len == 0) return 0;

    size_t first_chunk = MIN(max_len, rb->capacity - rb->read_client_ptr);
    if (dst) memcpy(dst, rb->buffer + rb->read_client_ptr, first_chunk);

    if (max_len > first_chunk) {
        if (dst) memcpy(dst + first_chunk, rb->buffer, max_len - first_chunk);
    }

    rb->read_client_ptr = (rb->read_client_ptr + max_len) % rb->capacity;
    return max_len;
}

/* ==================== SURICATA READER INTERFACE ==================== */

size_t dual_ring_buf_suri_read_available(dual_ring_buf_t *rb) {
    if (rb->write_ptr >= rb->read_suri_ptr) {
        return rb->write_ptr - rb->read_suri_ptr;
    }
    return rb->capacity - (rb->read_suri_ptr - rb->write_ptr);
}

size_t dual_ring_buf_suri_read(dual_ring_buf_t *rb, char *dst, size_t max_len) {
    size_t avail = dual_ring_buf_suri_read_available(rb);
    if (max_len > avail) max_len = avail;
    if (max_len == 0) return 0;

    size_t first_chunk = MIN(max_len, rb->capacity - rb->read_suri_ptr);
    if (dst) memcpy(dst, rb->buffer + rb->read_suri_ptr, first_chunk);

    if (max_len > first_chunk) {
        if (dst) memcpy(dst + first_chunk, rb->buffer, max_len - first_chunk);
    }

    rb->read_suri_ptr = (rb->read_suri_ptr + max_len) % rb->capacity;
    return max_len;
}
