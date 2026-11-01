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

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>

#include "srv_suricata.h"
#include "conn_table.h"

#include <netinet/in.h>

// With 2048 buckets and 8192 nodes, the load factor is 4.0.
// A load factor between 1.0 and 5.0 is considered fine for chained hash tables.
#define SURI_CONN_HASH_BUCKETS 2048 /* Power of 2 for fast masking */
#define SURI_CONN_MAX_NODES    8192 /* Fixed preallocated node capacity in SHM */
#define SURI_CONN_TTL_SEC      60   /* Expire unaccessed sessions after 60 seconds */
#define SURI_SHM_INVALID_IDX   -1

struct suri_conn_val {
    uint32_t client_seq;
    uint32_t server_seq;
    uint16_t icap_client_port;  /* Synthetic ICAP port created in REQMOD */
    time_t   last_seen;
};

struct suri_conn_node {
    struct suri_conn_key key;
    struct suri_conn_val val;
    int32_t next_idx;           /* SHM offset index instead of virtual address pointer */
    int in_use;
};

struct suri_conn_bucket {
    pthread_mutex_t lock;       /* Process-shared robust mutex */
    int32_t head_idx;
};

struct suri_conn_table {
    struct suri_conn_bucket buckets[SURI_CONN_HASH_BUCKETS];
    struct suri_conn_node   nodes[SURI_CONN_MAX_NODES];
    pthread_mutex_t         pool_lock;  /* Protects free-list allocations */
    int32_t                 free_head_idx;
};

static struct suri_conn_table *g_shm_conn_table = NULL;

/* Helper function to recover locks if a child process dies while holding a lock */
static inline int suri_shm_lock(pthread_mutex_t *mtx)
{
    int rc = pthread_mutex_lock(mtx);
#if defined(PTHREAD_MUTEX_ROBUST) || defined(EOWNERDEAD)
    if (rc == EOWNERDEAD) {
        suri_log(3, "Recovering robust mutex lock after child process termination\n");
#if defined(HAVE_PTHREAD_MUTEX_CONSISTENT) || defined(__GLIBC__) || defined(__linux__)
        pthread_mutex_consistent(mtx);
#endif
        return 0;
    }
#endif
    return rc;
}

static inline void suri_shm_unlock(pthread_mutex_t *mtx)
{
    pthread_mutex_unlock(mtx);
}

/* SHM slot allocation helpers */
static int32_t suri_shm_node_alloc(void)
{
    if (suri_shm_lock(&g_shm_conn_table->pool_lock) != 0) {
        return SURI_SHM_INVALID_IDX;
    }

    int32_t idx = g_shm_conn_table->free_head_idx;
    if (idx != SURI_SHM_INVALID_IDX) {
        struct suri_conn_node *n = &g_shm_conn_table->nodes[idx];
        g_shm_conn_table->free_head_idx = n->next_idx;
        n->next_idx = SURI_SHM_INVALID_IDX;
        n->in_use = 1;
    } else {
        suri_log(1, "SHM connection node pool exhausted! Increase SURI_CONN_MAX_NODES.\n");
    }

    suri_shm_unlock(&g_shm_conn_table->pool_lock);
    return idx;
}

static void suri_shm_node_free(int32_t idx)
{
    if (idx < 0 || idx >= SURI_CONN_MAX_NODES) return;

    if (suri_shm_lock(&g_shm_conn_table->pool_lock) != 0) {
        return;
    }

    struct suri_conn_node *n = &g_shm_conn_table->nodes[idx];
    memset(n, 0, sizeof(struct suri_conn_node));
    n->next_idx = g_shm_conn_table->free_head_idx;
    n->in_use = 0;
    g_shm_conn_table->free_head_idx = idx;

    suri_shm_unlock(&g_shm_conn_table->pool_lock);
}

void suri_conn_table_init(void)
{
    suri_log(5, "Initialize shared-memory connection table\n");

    size_t shm_size = sizeof(struct suri_conn_table);

    /* Allocate process-shared anonymous memory prior to fork() */
    g_shm_conn_table = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (g_shm_conn_table == MAP_FAILED) {
        suri_log(1, "mmap failed for shared-memory connection table\n");
        g_shm_conn_table = NULL;
        return;
    }

    memset(g_shm_conn_table, 0, shm_size);

    /* Setup mutex attributes conditionally */
    pthread_mutexattr_t mattr;
    pthread_mutexattr_init(&mattr);

#if defined(PTHREAD_PROCESS_SHARED) && !defined(__OpenBSD__)
    pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
#endif

#if defined(PTHREAD_MUTEX_ROBUST) && !defined(__OpenBSD__)
    pthread_mutexattr_setrobust(&mattr, PTHREAD_MUTEX_ROBUST);
#endif

    /* Initialize bucket mutexes */
    for (int i = 0; i < SURI_CONN_HASH_BUCKETS; i++) {
        pthread_mutex_init(&g_shm_conn_table->buckets[i].lock, &mattr);
        g_shm_conn_table->buckets[i].head_idx = SURI_SHM_INVALID_IDX;
    }

    /* Initialize pool mutex */
    pthread_mutex_init(&g_shm_conn_table->pool_lock, &mattr);
    pthread_mutexattr_destroy(&mattr);

    /* Link free nodes */
    for (int i = 0; i < SURI_CONN_MAX_NODES; i++) {
        g_shm_conn_table->nodes[i].next_idx = (i < SURI_CONN_MAX_NODES - 1) ? (i + 1) : SURI_SHM_INVALID_IDX;
        g_shm_conn_table->nodes[i].in_use = 0;
    }
    g_shm_conn_table->free_head_idx = 0;
}

void suri_conn_table_destroy(void)
{
    if (!g_shm_conn_table) return;

    suri_log(5, "Destroy shared-memory connection table\n");

    for (int i = 0; i < SURI_CONN_HASH_BUCKETS; i++) {
        struct suri_conn_bucket *b = &g_shm_conn_table->buckets[i];
        if (suri_shm_lock(&b->lock) == 0) {
            b->head_idx = SURI_SHM_INVALID_IDX;
            suri_shm_unlock(&b->lock);
        }
        pthread_mutex_destroy(&b->lock);
    }

    pthread_mutex_destroy(&g_shm_conn_table->pool_lock);
    munmap(g_shm_conn_table, sizeof(struct suri_conn_table));
    g_shm_conn_table = NULL;
}

static inline uint32_t suri_6tuple_hash(const struct suri_conn_key *k)
{
    /* 1. Fold 64-bit stream_id into 32 bits */
    uint32_t stream_mix = (uint32_t)(k->stream_id ^ (k->stream_id >> 32));

    /* 2. Mix high-entropy fields first (Stream ID & Source Port) */
    uint32_t h = stream_mix;
    h = (h * 31) + (uint32_t)k->src_port;

    /* 3. Add IP addresses and Destination Port */
    h = (h * 31) + k->src_ip;
    h = (h * 31) + k->dst_ip;
    h = (h * 31) + (uint32_t)k->dst_port;
    h = (h * 31) + (uint32_t)k->proto;

    /* 4. MurmurHash3 32-bit finalizer (fmix32) for full avalanche effect */
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;

    return h & (SURI_CONN_HASH_BUCKETS - 1);
}

static inline int suri_conn_key_equal(const struct suri_conn_key *a, const struct suri_conn_key *b)
{
    /* 1. Stream ID & Source Port (Highest entropy across H1/H2/H3) */
    if (a->stream_id != b->stream_id) return 0;
    if (a->src_port  != b->src_port)  return 0;

    /* 2. Source IP (High variance in multi-client production) */
    if (a->src_ip    != b->src_ip)    return 0;

    /* 3. Destination IP & Port (Moderate-to-low variance) */
    if (a->dst_ip    != b->dst_ip)    return 0;
    if (a->dst_port  != b->dst_port)  return 0;

    /* 4. Protocol (Lowest entropy - usually H2 or H3) */
    return (a->proto == b->proto);
}

int suri_conn_table_set(const struct suri_conn_key *key, uint32_t client_seq, uint32_t server_seq, uint16_t icap_client_port)
{
    if (!g_shm_conn_table) return -1;

    uint32_t idx = suri_6tuple_hash(key);
    struct suri_conn_bucket *b = &g_shm_conn_table->buckets[idx];

    if (suri_shm_lock(&b->lock) != 0) {
        return -1;
    }

    int32_t curr_idx = b->head_idx;
    int32_t prev_idx = SURI_SHM_INVALID_IDX;
    time_t now = time(NULL);

    while (curr_idx != SURI_SHM_INVALID_IDX) {
        struct suri_conn_node *curr = &g_shm_conn_table->nodes[curr_idx];
        int32_t next_idx = curr->next_idx;

        /* Purge expired node while iterating */
        if (now - curr->val.last_seen > SURI_CONN_TTL_SEC) {
            if (prev_idx != SURI_SHM_INVALID_IDX) {
                g_shm_conn_table->nodes[prev_idx].next_idx = next_idx;
            } else {
                b->head_idx = next_idx;
            }

            suri_log(7, "Purge stale connection during set for key hash index: %u, client seq: %u, server seq: %u, icap client port: %u\n",
                idx, curr->val.client_seq, curr->val.server_seq, ntohs(curr->val.icap_client_port));

            suri_shm_node_free(curr_idx);
            curr_idx = next_idx;
            continue;
        }

        /* Key match: update sequence numbers */
        if (suri_conn_key_equal(&curr->key, key)) {
            curr->val.client_seq = client_seq;
            curr->val.server_seq = server_seq;
            curr->val.icap_client_port = icap_client_port;
            curr->val.last_seen = now;

            suri_log(7, "Update connection for key hash index: %u, client seq: %u, server seq: %u, icap client port: %u\n",
                idx, curr->val.client_seq, curr->val.server_seq, ntohs(curr->val.icap_client_port));

            suri_shm_unlock(&b->lock);
            return 0;
        }

        prev_idx = curr_idx;
        curr_idx = next_idx;
    }

    suri_log(7, "Set connection for key hash index: %u, client seq: %u, server seq: %u, icap client port: %u\n",
        idx, client_seq, server_seq, ntohs(icap_client_port));

    /* Key not found: allocate new node slot from SHM pool */
    int32_t new_idx = suri_shm_node_alloc();
    if (new_idx == SURI_SHM_INVALID_IDX) {
        suri_log(1, "suri_shm_node_alloc failed for new connection node\n");
        suri_shm_unlock(&b->lock);
        return -1;
    }

    struct suri_conn_node *new_node = &g_shm_conn_table->nodes[new_idx];
    new_node->key = *key;
    new_node->val.client_seq = client_seq;
    new_node->val.server_seq = server_seq;
    new_node->val.icap_client_port = icap_client_port;
    new_node->val.last_seen = now;
    new_node->next_idx = b->head_idx;
    b->head_idx = new_idx;

    suri_shm_unlock(&b->lock);
    return 0;
}

int suri_conn_table_get(const struct suri_conn_key *key, uint32_t *client_seq, uint32_t *server_seq, uint16_t *icap_client_port, int delete)
{
    if (!g_shm_conn_table) return 0;

    uint32_t idx = suri_6tuple_hash(key);
    struct suri_conn_bucket *b = &g_shm_conn_table->buckets[idx];

    if (suri_shm_lock(&b->lock) != 0) {
        return 0;
    }

    int32_t curr_idx = b->head_idx;
    int32_t prev_idx = SURI_SHM_INVALID_IDX;
    time_t now = time(NULL);
    int found = 0;

    while (curr_idx != SURI_SHM_INVALID_IDX) {
        struct suri_conn_node *curr = &g_shm_conn_table->nodes[curr_idx];
        int32_t next_idx = curr->next_idx;

        /* 1. KEY MATCH (Even if expired - fetch and evict) */
        if (suri_conn_key_equal(&curr->key, key)) {
            suri_log(7, "Get%s connection for key hash index: %u, client seq: %u, server seq: %u, icap client port: %u\n",
                delete ? " and delete" : "", idx, curr->val.client_seq, curr->val.server_seq, ntohs(curr->val.icap_client_port));

            if (client_seq)       *client_seq = curr->val.client_seq;
            if (server_seq)       *server_seq = curr->val.server_seq;
            if (icap_client_port) *icap_client_port = curr->val.icap_client_port;

            if (prev_idx != SURI_SHM_INVALID_IDX) {
                g_shm_conn_table->nodes[prev_idx].next_idx = next_idx;
            } else {
                b->head_idx = next_idx;
            }

            if (delete) {
                suri_shm_node_free(curr_idx);
            }
            found = 1;
            break;
        }

        /* 2. INLINE PURGE: Evict non-matching stale nodes encountered while traversing */
        if (now - curr->val.last_seen > SURI_CONN_TTL_SEC) {
            suri_log(7, "Purge stale connection during get for key hash index: %u, client seq: %u, server seq: %u, icap client port: %u\n",
                idx, curr->val.client_seq, curr->val.server_seq, ntohs(curr->val.icap_client_port));

            if (prev_idx != SURI_SHM_INVALID_IDX) {
                g_shm_conn_table->nodes[prev_idx].next_idx = next_idx;
            } else {
                b->head_idx = next_idx;
            }

            suri_shm_node_free(curr_idx);
            curr_idx = next_idx;
            /* ATTENTION: prev_idx remains unchanged because the node at curr_idx was removed! */
            continue;
        }

        /* 3. ADVANCE POINTERS (Only reached for valid non-matching nodes) */
        prev_idx = curr_idx;
        curr_idx = next_idx;
    }

    if (!found) {
        suri_log(7, "Cannot find connection for key hash index: %u\n", idx);
    }

    suri_shm_unlock(&b->lock);
    return found;
}
