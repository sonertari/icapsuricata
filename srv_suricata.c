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

/*
 * srv_suricata.c — c-icap service module using libsuricata
 *
 * Architecture:
 *   - Standard c-icap service module (ci_service_module_t) pattern, mirroring
 *     the upstream "echo" service.
 *   - Suricata is initialised in library mode (RUNMODE_LIB) inside the module's
 *     init function, loading a single hard-coded alert rule.
 *   - Incoming HTTP body chunks (preview + streaming IO) are reassembled into a
 *     buffer and injected into Suricata as synthetic TCP payload packets so the
 *     detection engine can evaluate them.
 *   - On a rule match Suricata fires its normal alert path; we additionally hook
 *     the PacketAlert callback to return the verdict to client.
 *
 * Build:
 *   See Makefile in the same directory.
 *
 * References:
 *   • c-icap echo service  — services/echo/srv_echo.c
 *   • libsuricata custom   — examples/lib/custom/main.c
 *   • Suricata lib API     — src/suricata.h, src/lib.h, src/detect.h
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

// Adjust the include path in the Makefile if your installation places these headers differently
#include <c_icap/c-icap.h>
#include <c_icap/service.h>
#include <c_icap/header.h>
#include <c_icap/body.h>
#include <c_icap/simple_api.h>
#include <c_icap/debug.h>
#include <c_icap/cfg_param.h>
#include <c_icap/commands.h>

// These headers are installed via `make install-headers`
#include <suricata/suricata.h>
#include <suricata/detect.h>
#include <suricata/conf.h>
#include <suricata/runmodes.h>
#include <suricata/tm-threads.h>
#include <suricata/util-debug.h>
#include <suricata/packet.h>
#include <suricata/decode.h>
#include <suricata/util-time.h>
#include <suricata/runmode-lib.h>
#include <suricata/action-globals.h>

// TODO: Remove after Suricata headers are refactored to not conflict with netinet/tcp.h
// These headers are defined in suricata/stream-tcp-private.h, and they conflict with netinet/tcp.h
// Temporarily rename the conflicting symbols to protect them from netinet/tcp.h
#define TCP_SYN_SENT    SURI_TCP_SYN_SENT
#define TCP_SYN_RECV    SURI_TCP_SYN_RECV
#define TCP_ESTABLISHED SURI_TCP_ESTABLISHED
#define TCP_FIN_WAIT1   SURI_TCP_FIN_WAIT1
#define TCP_FIN_WAIT2   SURI_TCP_FIN_WAIT2
#define TCP_TIME_WAIT   SURI_TCP_TIME_WAIT
#define TCP_LAST_ACK    SURI_TCP_LAST_ACK
#define TCP_CLOSE_WAIT  SURI_TCP_CLOSE_WAIT
#define TCP_CLOSING     SURI_TCP_CLOSING
#define TCP_CLOSED      SURI_TCP_CLOSED

#include <suricata/stream-tcp.h>

// For synthetic buffer construction
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "dual_ring_buf.h"

#define SURI_BODY_BUF_SIZE (64 * 1024)  /* 64 KiB */
#define SURI_MAX_HTTP_HDRS (16 * 1024)  /* 16 KiB */

#define suri_log(LEVEL, format_str, ...) \
    ci_debug_printf(LEVEL, "srv_suricata: %s: " format_str, __FUNCTION__, ##__VA_ARGS__)

// Thread-local variables: one ThreadVars per c-icap worker thread, no mutex needed.
static pthread_key_t g_worker_tv_key;
static int g_worker_id_counter = 1;    /* bootstrap TV uses id=1; c-icap threads start from 2 */

// Bootstrap ThreadVars: created in SuricataRunModeSetup (during SuricataInit) so that
// SuricataPostInit/TmThreadWaitOnThreadInit can find it.  The dedicated worker thread
// calls SCRunModeLibSpawnWorker on this TV and then blocks in SuricataMainLoop.
static ThreadVars *g_worker_tv = NULL;

// pthread_t of the dedicated worker thread (used for pthread_join in shutdown).
static pthread_t g_worker_thread_id = 0;

// Global list of lazily-created per-c-icap-thread TVs, used during shutdown to free
// in suri_close_service().
#define SURI_MAX_LAZY_TVS 128
static ThreadVars *g_lazy_tvs[SURI_MAX_LAZY_TVS];
static int g_lazy_tv_count = 0;
static pthread_mutex_t g_lazy_tv_lock = PTHREAD_MUTEX_INITIALIZER;

static int         g_suri_ready = 0;   /* set to 1 after SuricataPostInit */
static pid_t       g_parent_pid = 0;   /* Tracks which process initialized Suricata */

enum suri_conn_state {
    SYN = 0,
    SYN_ACK,
    ACK,
    ESTABLISHED,
    FIN
};

// Per-request data structure
struct suri_ctx {
    dual_ring_buf_t *body_buf;       /* accumulation buffer */
    unsigned int injected_since_ack; /* bytes injected to Suricata since last ACK */

    unsigned int eof : 1;
    unsigned int block : 1;
    unsigned int error : 1;

    uint32_t client_ip;
    unsigned int client_ip_set : 1;
    uint16_t client_port;
    unsigned int client_port_set : 1;
    uint16_t icap_client_port;
    unsigned int icap_client_port_set : 1;
    uint32_t server_ip;
    unsigned int server_ip_set : 1;
    uint16_t server_port;
    unsigned int server_port_set : 1;
    uint8_t  proto;
    unsigned int proto_set : 1;
    LiveDevice *dev;
    unsigned int dev_set : 1;

    uint32_t client_seq;
    uint32_t client_ack;
    uint32_t server_seq;
    uint32_t server_ack;
    enum suri_conn_state state;

    // __suseconds_t tv_usec;
};

enum suri_mode {mode_disallow204, mode_allow204};
static int SURI_MODE = mode_allow204;

// The c-icap wbuf size is usually 4064 bytes, so pick a threshold slightly below that
// Setting ACKWINDOW to 0 disables ACK injection
static unsigned int SURI_ACKWINDOW = 4000;  /* bytes */

static unsigned int SURI_PREVIEW = SURI_BODY_BUF_SIZE;  /* bytes */

// SURI_BUFSIZE should be larger than or equal to SURI_PREVIEW, otherwise we cannot buffer preview data
static unsigned int SURI_BUFSIZE = SURI_BODY_BUF_SIZE;  /* bytes */

static int  suri_cfg_mode(const char *directive, const char **argv, void *setdata);
static int  suri_cfg_ackwindow(const char *directive, const char **argv, void *setdata);
static int  suri_cfg_preview(const char *directive, const char **argv, void *setdata);
static int  suri_cfg_bufsize(const char *directive, const char **argv, void *setdata);

static struct ci_conf_entry suri_conf_variables[] = {
    {"Mode", NULL, suri_cfg_mode, NULL},
    {"ACKwindow", NULL, suri_cfg_ackwindow, NULL},
    // PreviewSize is a standard c-icap directive, but we re-define it here to enforce the bufsize >= preview constraint
    {"Preview", NULL, suri_cfg_preview, NULL},
    {"BufSize", NULL, suri_cfg_bufsize, NULL},
    {NULL, NULL, NULL, NULL}
};

int  suri_init_service(ci_service_xdata_t *srv_xdata, struct ci_server_conf *server_conf);
int  suri_post_init_service(ci_service_xdata_t * srv_xdata, struct ci_server_conf *server_conf);
void suri_close_service(void);
void *suri_init_request_data(ci_request_t *req);
void suri_release_request_data(void *data);
int  suri_check_preview_handler(char *preview_data, int preview_data_len, ci_request_t *req);
int  suri_end_of_data_handler(ci_request_t *req);
int  suri_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof, ci_request_t *req);

static ci_service_module_t suricata_service = {
    "suricata",                         /* mod_name                  */
    "Suricata ICAP service",            /* mod_short_descr           */
    ICAP_RESPMOD | ICAP_REQMOD,         /* mod_type                  */
    suri_init_service,                  /* mod_init_service          */
    suri_post_init_service,             /* post_init_service         */
    suri_close_service,                 /* mod_close_service         */
    suri_init_request_data,             /* mod_init_request_data     */
    suri_release_request_data,          /* mod_release_request_data  */
    suri_check_preview_handler,         /* mod_check_preview_handler */
    suri_end_of_data_handler,           /* mod_end_of_data_handler   */
    suri_io,                            /* mod_service_io            */
    suri_conf_variables,                /* conf_variables            */
    NULL                                /* xdata                     */
};

// Macro that registers the service with c-icap's module loader
_CI_DECLARE_SERVICE(suricata_service);

// Destruction callback triggered automatically when a c-icap worker thread terminates.
// SCTmThreadsSlotPacketLoopFinish() is NOT called here because it requires THV_DEINIT
// to be set first (by SuricataShutdown), and the c-icap thread may exit before or
// after shutdown.  Instead, suri_close_service() frees all lazy TVs during the 
// shutdown sequence.
static void ThreadVarsDestroyCallback(void *value)
{
    (void)value;
    // TV lifetime is managed by suri_close_service() at shutdown.
}

// The library runmode MUST create at least one ThreadVars here (inside SuricataInit)
// so that SuricataPostInit/TmThreadWaitOnThreadInit can account for it.
// Creating TVs after SuricataInit returns is too late: TmThreadWaitOnThreadInit would
// time out waiting for THV_INIT_DONE on any TV registered but never spawned.
static int SuricataRunModeSetup(void)
{
    suri_log(7, "ENTER\n");

    // TimeModeSetOffline: we feed synthetic packets with fabricated timestamps,
    // so we do not want the engine to complain about clock skew.
    TimeModeSetOffline();

    g_worker_tv = SCRunModeLibCreateThreadVars(1 /* worker_id */);
    if (g_worker_tv == NULL) {
        suri_log(1, "SCRunModeLibCreateThreadVars failed\n");
        return -1;
    }

    suri_log(9, "EXIT, g_worker_tv->id=%d\n", g_worker_tv->id);
    return 0;
}

// Packet injection helper
static void ReleasePacket(Packet *p)
{
    suri_log(9, "ENTER\n");
    if (PacketCheckAction(p, ACTION_DROP)) {
        suri_log(5, "Dropping packet!\n");
    }

    if (p->ext_pkt != NULL) {
        suri_log(9, "Freeing packet buffer\n");
        // This is the buffer allocated while injecting the packet
        free(p->ext_pkt);
        p->ext_pkt = NULL;
    }

    // As we overode the default release function, we must release or
    // free the packet.
    PacketFreeOrRelease(p);
}

static uint8_t RateFilterCallback(const Packet *p, const uint32_t sid, const uint32_t gid,
        const uint32_t rev, uint8_t original_action, uint8_t new_action, void *arg)
{
    // Don't change the action
    return new_action;
}

// Helper: lazily create and spawn a per-c-icap-thread ThreadVars.
// Each c-icap worker thread gets its own TV so TmThreadsSlotProcessPkt()
// can be called concurrently without a global mutex.
//
// IMPORTANT: TVs created after SuricataPostInit() have THV_PAUSE set by
// default (every new TV does).  TmThreadContinueThreads() already ran inside
// SuricataPostInit(), so it will never run again to clear that flag.
// We call TmThreadContinue(tv) manually to clear THV_PAUSE before invoking
// SCRunModeLibSpawnWorker(), which otherwise deadlocks inside
// TmThreadsWaitForUnpause().
static ThreadVars *GetThreadWorkerVars(void)
{
    ThreadVars *tv = pthread_getspecific(g_worker_tv_key);
    if (unlikely(tv == NULL)) {
        int worker_id = __sync_add_and_fetch(&g_worker_id_counter, 1);
        suri_log(5, "Initializing thread-local ThreadVars, worker_id=%d\n", worker_id);

        tv = SCRunModeLibCreateThreadVars(worker_id);
        if (tv == NULL) {
            suri_log(1, "Critical: SCRunModeLibCreateThreadVars failed, worker_id=%d\n", worker_id);
            return NULL;
        }

        // Every new TV starts paused.  TmThreadContinueThreads() already ran
        // during SuricataPostInit() so we must clear THV_PAUSE manually here.
        TmThreadContinue(tv);

        // ATTENTION: SCRunModeLibSpawnWorker will not spawn the worker thread a second time 
        if (SCRunModeLibSpawnWorker(tv) != 0) {
            suri_log(1, "Critical: SCRunModeLibSpawnWorker failed, worker_id=%d\n", worker_id);
            return NULL;
        }

        pthread_setspecific(g_worker_tv_key, tv);

        // Register in the global list so suri_close_service() can free
        // each TV at shutdown.
        pthread_mutex_lock(&g_lazy_tv_lock);
        if (g_lazy_tv_count < SURI_MAX_LAZY_TVS) {
            g_lazy_tvs[g_lazy_tv_count++] = tv;
        } else {
            suri_log(1, "SURI_MAX_LAZY_TVS (%d) exceeded; increase the limit\n", SURI_MAX_LAZY_TVS);
        }
        pthread_mutex_unlock(&g_lazy_tv_lock);
        suri_log(5, "EXIT, worker_id=%d, tv->id=%d\n", worker_id, tv->id);
    }
    return tv;
}

static void suri_unlink_tv_from_root(ThreadVars *tv_to_remove)
{
    if (tv_to_remove == NULL) return;

    int type = tv_to_remove->type;
    if (type < 0 || type >= TVT_MAX) return;

    ThreadVars *curr = tv_root[type];
    ThreadVars *prev = NULL;

    while (curr != NULL) {
        if (curr == tv_to_remove) {
            if (prev == NULL) {
                /* Node to remove is the head of the list */
                tv_root[type] = curr->next;
            } else {
                /* Node to remove is in the middle or end */
                prev->next = curr->next;
            }
            curr->next = NULL;
            return;
        }
        prev = curr;
        curr = curr->next;
    }
}

static void suri_free_tv(ThreadVars *tv)
{
    if (tv == NULL) return;

    TmSlot *s = tv->tm_slots;

    /* Flush local counters to global stats */
    StatsSyncCounters(tv);

    /* Run thread slot deinitialization (frees detection engine contexts, 
       thread-local caches, packet pools) without touching flow loops */
    PacketPoolDestroy();

    for (TmSlot *slot = s; slot != NULL; slot = slot->slot_next) {
        if (slot->SlotThreadExitPrintStats != NULL) {
            slot->SlotThreadExitPrintStats(tv, SC_ATOMIC_GET(slot->slot_data));
        }
        if (slot->SlotThreadDeinit != NULL) {
            slot->SlotThreadDeinit(tv, SC_ATOMIC_GET(slot->slot_data));
        }
    }

    tv->stream_pq = NULL;
    TmThreadsSetFlag(tv, THV_CLOSED);

    TmThreadsUnregisterThread(tv->id);

    /* CRITICAL: Forcibly unlink TV from tv_root BEFORE freeing memory */
    SCMutexLock(&tv_root_lock);
    suri_unlink_tv_from_root(tv);
    SCMutexUnlock(&tv_root_lock);

    ThreadVarsFree(tv);
}

// Dedicated worker thread: spawns the bootstrap TV (blocks in TmThreadsWaitForUnpause
// until SuricataPostInit calls TmThreadContinueThreads), then drives SuricataMainLoop.
//
// At shutdown SuricataMainLoop() returns (EngineStop() set SURICATA_STOP).
static void *SuricataWorkerThread(void *arg)
{
    (void)arg;

    suri_log(5, "ENTER, start main worker thread, g_worker_tv->id=%d\n", g_worker_tv->id);

    // g_worker_tv was created in SuricataRunModeSetup (during SuricataInit).
    // It is already registered in tv_root so TmThreadWaitOnThreadInit can find it.
    if (SCRunModeLibSpawnWorker(g_worker_tv) != 0) {
        suri_log(1, "SCRunModeLibSpawnWorker failed for bootstrap TV\n");
        pthread_exit((void *)(intptr_t)EXIT_FAILURE);
    }

    suri_log(5, "SuricataMainLoop()\n");
    SuricataMainLoop();

    // --- Shutdown path ---
    // ATTENTION: We don't call SCTmThreadsSlotPacketLoopFinish for either the bootstrap TV
    // or the lazily-created TVs. Nor do we call SuricataShutdown() here.

    // suri_log(5, "SCTmThreadsSlotPacketLoopFinish() for bootstrap TV, g_worker_tv->id=%d\n", g_worker_tv->id);
    // SCTmThreadsSlotPacketLoopFinish(g_worker_tv);

    // Also finish all lazily-created per-c-icap-thread TVs.
    // pthread_mutex_lock(&g_lazy_tv_lock);
    // int count = g_lazy_tv_count;
    // pthread_mutex_unlock(&g_lazy_tv_lock);

    // for (int i = 0; i < count; i++) {
    //     suri_log(5, "SCTmThreadsSlotPacketLoopFinish() for lazy TV %d\n", i);
    //     SCTmThreadsSlotPacketLoopFinish(g_lazy_tvs[i]);
    // }

    // suri_log(7, "SuricataShutdown()\n");
    // SuricataShutdown();

    // ATTENTION: Do not free the bootstrap TV here, otherwise pthread_exit() may hang on OpenBSD.
    // Clean up and UNLINK the bootstrap TV (g_worker_tv / W#01)
    // suri_log(7, "Unlink and free bootstrap TV [%s]\n", g_worker_tv->name);
    // suri_free_tv(g_worker_tv);
    // g_worker_tv = NULL;

    suri_log(5, "EXIT\n");
    pthread_exit((void *)(intptr_t)EXIT_SUCCESS);
}

// Minimal 40-byte raw Layer 3 / Layer 4 structure 
// packed to ensure precise network formatting alignment.
struct __attribute__((__packed__)) fake_pkt_hdr {
#ifdef __linux__
    struct iphdr ip;
#else
    struct ip ip;
#endif
    struct tcphdr tcp;
};

static uint32_t GetClientIP(ci_request_t *req)
{
    struct suri_ctx *ctx = ci_service_data(req);

    if (ctx->client_ip_set) {
        return ctx->client_ip;
    }

    ctx->client_ip = htonl(0x7F000001);  /* Fallback to 127.0.0.1 */
    ctx->client_ip_set = 1;

    const char *ip_str = ci_icap_request_get_header(req, "X-Client-IP");
    if (ip_str) {
        inet_pton(AF_INET, ip_str, &ctx->client_ip);
    }

    suri_log(9, "X-Client-IP=%s\n", ip_str ? ip_str : "not set, using fallback");
    return ctx->client_ip;
}

static uint16_t GetClientPort(ci_request_t *req)
{
    struct suri_ctx *ctx = ci_service_data(req);

    if (ctx->client_port_set) {
        return ctx->client_port;
    }

    ctx->client_port = htons(12345);  /* Fallback to 12345 */
    ctx->client_port_set = 1;

    const char *port_str = ci_icap_request_get_header(req, "X-Client-Port");
    if (port_str) {
        ctx->client_port = htons(atoi(port_str));
    }

    suri_log(9, "X-Client-Port=%s\n", port_str ? port_str : "not set, using fallback");
    return ctx->client_port;
}

static uint16_t GetIcapClientPort(ci_request_t *req)
{
    struct suri_ctx *ctx = ci_service_data(req);

    if (ctx->icap_client_port_set) {
        return ctx->icap_client_port;
    }

    ctx->icap_client_port = GetClientPort(req);  /* Fallback to X-Client-Port */
    ctx->icap_client_port_set = 1;

    if (req && req->connection) {
        int icap_fd = req->connection->fd;

        if (icap_fd >= 0) {
            struct sockaddr_storage local_addr;
            socklen_t addr_len = sizeof(local_addr);

            // Get the remote port of the ICAP client connection (ephemeral port)
            // to isolate different processing stream channels onto separate ports
            if (getpeername(icap_fd, (struct sockaddr *)&local_addr, &addr_len) == 0) {
                if (local_addr.ss_family == AF_INET) {
                    struct sockaddr_in *s = (struct sockaddr_in *)&local_addr;
                    ctx->icap_client_port = s->sin_port;
                } else if (local_addr.ss_family == AF_INET6) {
                    struct sockaddr_in6 *s = (struct sockaddr_in6 *)&local_addr;
                    ctx->icap_client_port = s->sin6_port;
                }
            }
        }
    }

    suri_log(9, "ICAP client port: %u\n", ntohs(ctx->icap_client_port));
    return ctx->icap_client_port;
}

static uint32_t GetServerIP(ci_request_t *req)
{
    struct suri_ctx *ctx = ci_service_data(req);

    if (ctx->server_ip_set) {
        return ctx->server_ip;
    }

    ctx->server_ip = htonl(0x7F000001);  /* Fallback to 127.0.0.1 */
    ctx->server_ip_set = 1;

    const char *ip_str = ci_icap_request_get_header(req, "X-Server-IP");
    if (ip_str) {
        inet_pton(AF_INET, ip_str, &ctx->server_ip);
    }

    suri_log(9, "X-Server-IP=%s\n", ip_str ? ip_str : "not set, using fallback");
    return ctx->server_ip;
}

static uint32_t GetServerPort(ci_request_t *req)
{
    struct suri_ctx *ctx = ci_service_data(req);

    if (ctx->server_port_set) {
        return ctx->server_port;
    }

    ctx->server_port = htons(80);  /* Fallback to 80 */
    ctx->server_port_set = 1;

    const char *port_str = ci_icap_request_get_header(req, "X-Server-Port");
    if (port_str) {
        ctx->server_port = htons(atoi(port_str));
    }

    suri_log(9, "X-Server-Port=%s\n", port_str ? port_str : "not set, using fallback");
    return ctx->server_port;
}

static uint8_t GetProto(ci_request_t *req)
{
    struct suri_ctx *ctx = ci_service_data(req);

    if (ctx->proto_set) {
        return ctx->proto;
    }

    ctx->proto = IPPROTO_TCP;     /* Default to TCP */
    ctx->proto_set = 1;

    const char *proto_str = ci_icap_request_get_header(req, "X-Proto");
    if (proto_str && strcasecmp(proto_str, "UDP") == 0) {
        ctx->proto = IPPROTO_UDP;
    }

    suri_log(9, "X-Proto=%s\n", proto_str ? proto_str : "not set, using default TCP");
    return ctx->proto;
}

static LiveDevice *GetLiveDevice(ci_request_t *req)
{
    struct suri_ctx *ctx = ci_service_data(req);

    if (ctx->dev_set) {
        return ctx->dev;
    }

    ctx->dev_set = 1;

    ctx->dev = LiveGetDevice("suri_icap0");
    if (ctx->dev == NULL) {
        suri_log(1, "LiveGetDevice failed\n");
    }
    else {
        suri_log(5, "Obtained LiveDevice for injection\n");
    }

    return ctx->dev;
}

static void GetSeqAck(ci_request_t *req, size_t len, int toserver)
{
    struct suri_ctx *ctx = ci_service_data(req);

    // ISNs are assigned in preview handler
    if (ctx->state == SYN) {
        ctx->state = SYN_ACK;
    }
    else if (ctx->state == SYN_ACK) {
        ctx->server_ack = ctx->client_seq + 1;  // SYN consumes one sequence number
        ctx->state = ACK;
    }
    else if (ctx->state == ACK) {
        ctx->client_seq = ctx->server_ack;
        ctx->client_ack = ctx->server_seq + 1;
        ctx->state = ESTABLISHED;
    }
    else if (ctx->state == ESTABLISHED) {
        if (toserver) {
            ctx->client_seq = ctx->server_ack;
            ctx->server_ack = ctx->client_seq + len;
        }
        else {
            ctx->server_seq = ctx->client_ack;
            ctx->client_ack = ctx->server_seq + len;
        }
    }
    else if (ctx->state == FIN) {
        if (toserver) {
            ctx->client_seq = ctx->server_ack;
            ctx->server_ack = ctx->client_seq + 1;  // FIN consumes one sequence number
        }
        else {
            ctx->server_seq = ctx->client_ack;
            ctx->client_ack = ctx->server_seq + 1;
        }
    }
    suri_log(9, "client_seq=%u, client_ack=%u, server_seq=%u, server_ack=%u\n",
                    ctx->client_seq, ctx->client_ack, ctx->server_seq, ctx->server_ack);
}

// Create emulated packet
static uint8_t *CreatePacket(ci_request_t *req, const char *data, int data_len, uint16_t flags, int toserver, size_t *pkt_len)
{
    struct suri_ctx *ctx = ci_service_data(req);

    size_t header_len = sizeof(struct fake_pkt_hdr);
    // Allocate 4 extra bytes for the TCP option (Kind + Length + 2-byte Port)
    size_t opt_len = (GetProto(req) == IPPROTO_TCP) ? 4 : 0;

    *pkt_len = header_len + opt_len + data_len;

    uint8_t *pkt = malloc(*pkt_len);
    if (pkt == NULL) {
        suri_log(1, "malloc failed for pkt\n");
        return NULL;
    }

    // Zero out both the fake header block and the option block
    memset(pkt, 0, header_len + opt_len);

    struct fake_pkt_hdr *hdr = (struct fake_pkt_hdr *)pkt;

#ifdef __linux__
    // Linux struct iphdr and struct tcphdr field mappings
    hdr->ip.version = 4;
    hdr->ip.ihl = 5;                        /* 5 dwords = 20 bytes */
    hdr->ip.tot_len = htons(*pkt_len);
    hdr->ip.ttl = 64;

    hdr->ip.protocol = GetProto(req);

    suri_log(9, "Set IP/Port, direction to %s\n", toserver ? "server" : "client");
    hdr->ip.saddr = toserver ? GetClientIP(req) : GetServerIP(req);
    hdr->ip.daddr = toserver ? GetServerIP(req) : GetClientIP(req);

    if (hdr->ip.protocol == IPPROTO_TCP) {
        // Use ICAP client port for the standard L4 tuple
        // This allows Suricata to distinguish different h2/h3 streams.
        hdr->tcp.th_sport = toserver ? GetIcapClientPort(req) : GetServerPort(req);
        hdr->tcp.th_dport = toserver ? GetServerPort(req) : GetIcapClientPort(req);

        hdr->tcp.doff = 6;                  /* 6 dwords = 24 bytes (20B header + 4B option) */
        hdr->tcp.syn = flags & TH_SYN ? 1 : 0;
        hdr->tcp.ack = flags & TH_ACK ? 1 : 0;
        hdr->tcp.psh = flags & TH_PUSH ? 1 : 0;
        hdr->tcp.fin = flags & TH_FIN ? 1 : 0;

        suri_log(7, "Set flags syn=%u, ack=%u, psh=%u, fin=%u\n", hdr->tcp.syn, hdr->tcp.ack, hdr->tcp.psh, hdr->tcp.fin);
#else
    // BSD struct ip and struct tcphdr field mappings
    hdr->ip.ip_v = 4;
    hdr->ip.ip_hl = 5;                        /* 5 dwords = 20 bytes */
    hdr->ip.ip_len = htons(*pkt_len);
    hdr->ip.ip_ttl = 64;
    hdr->ip.ip_p = GetProto(req);

    suri_log(9, "Set IP/Port, direction to %s\n", toserver ? "server" : "client");
    hdr->ip.ip_src.s_addr = toserver ? GetClientIP(req) : GetServerIP(req);
    hdr->ip.ip_dst.s_addr = toserver ? GetServerIP(req) : GetClientIP(req);

    if (hdr->ip.ip_p == IPPROTO_TCP) {
        // Use ICAP client port for the standard L4 tuple
        // This allows Suricata to distinguish different h2/h3 streams.
        hdr->tcp.th_sport = toserver ? GetIcapClientPort(req) : GetServerPort(req);
        hdr->tcp.th_dport = toserver ? GetServerPort(req) : GetIcapClientPort(req);

        hdr->tcp.th_off = 6;                  /* 6 dwords = 24 bytes (20B header + 4B option) */

        // BSD TCP flag handling
        if (flags & TH_SYN)  hdr->tcp.th_flags |= TH_SYN;
        if (flags & TH_ACK)  hdr->tcp.th_flags |= TH_ACK;
        if (flags & TH_PUSH) hdr->tcp.th_flags |= TH_PUSH;
        if (flags & TH_FIN)  hdr->tcp.th_flags |= TH_FIN;

        suri_log(7, "Set flags syn=%u, ack=%u, psh=%u, fin=%u\n",
                 (hdr->tcp.th_flags & TH_SYN) ? 1 : 0,
                 (hdr->tcp.th_flags & TH_ACK) ? 1 : 0,
                 (hdr->tcp.th_flags & TH_PUSH) ? 1 : 0,
                 (hdr->tcp.th_flags & TH_FIN) ? 1 : 0);
#endif

        // ATTENTION: Suricata does NOT detect unless we set th_win (otherwise, flow will have error events)
        hdr->tcp.th_win = htons(65535);

        GetSeqAck(req, data_len, toserver);

        hdr->tcp.th_seq = toserver ? htonl(ctx->client_seq) : htonl(ctx->server_seq);
        hdr->tcp.th_ack = toserver ? htonl(ctx->client_ack) : htonl(ctx->server_ack);

        // Inject the actual client port as a TCP option
        uint8_t *opt_ptr = pkt + header_len;
        uint16_t actual_client_port = GetClientPort(req);

        opt_ptr[0] = 78;   // Option Kind: Historical Proxy/Enterprise Option
        opt_ptr[1] = 4;    // Option Length: 4 bytes total
        opt_ptr[2] = (actual_client_port >> 8) & 0xFF; // Port high byte
        opt_ptr[3] = actual_client_port & 0xFF;        // Port low byte

        // Revert byte order for printing
        suri_log(7, "Set %s seq=%u, ack=%u, real_port=%u, icap_client_port=%u\n",
                 toserver ? "client" : "server", ntohl(hdr->tcp.th_seq), ntohl(hdr->tcp.th_ack),
                 ntohs(actual_client_port), ntohs(GetIcapClientPort(req)));
    }

    if (data_len > 0) {
        // Shift data target forward to account for the option length
        memcpy(pkt + header_len + opt_len, data, data_len);
    }
    return pkt;
}

// InjectPacket — wrap raw bytes in a minimal Suricata Packet and push
// it through the detection engine.
// We present the payload as a raw segment on a fake loopback device.
static int InjectPacket(ci_request_t *req, const char *data, int data_len, uint16_t flags, int toserver)
{
    // Pull the unique thread-local worker context safely from key storage
    ThreadVars *my_tv = GetThreadWorkerVars();
    if (!g_suri_ready || my_tv == NULL) {
        suri_log(3, "Engine context not ready, skipping packet injection\n");
        return -1;
    }

    size_t pkt_len = 0;

    uint8_t *pkt = CreatePacket(req, data, data_len, flags, toserver, &pkt_len);
    if (pkt == NULL) {
        return -1;
    }

    if (GetLiveDevice(req) == NULL) {
        free(pkt);
        return -1;
    }

    Packet *p = PacketGetFromQueueOrAlloc();
    if (unlikely(p == NULL)) {
        suri_log(1, "PacketGetFromQueueOrAlloc failed\n");
        free(pkt);
        return -1;
    }

    // Hand over the synthesized buffer to the Suricata Packet allocation
    if (PacketSetData(p, pkt, pkt_len) == -1) {
        suri_log(1, "PacketSetData failed\n");
        free(pkt);
        TmqhOutputPacketpool(my_tv, p);
        return -1;
    }

    // Timestamp — engine is in offline mode, so any value is fine.
    struct timeval tv;
    gettimeofday(&tv, NULL);

    // No need to add extra offsets, Suricata detects with current time
    // struct suricata_req_data *d = ci_service_data(req);
    // tv.tv_usec += d->tv_usec;  /* Add some microsecond offset to differentiate packets in the same request */
    // d->tv_usec += 5000;        /* Increment offset for next packet in the same request */
    // suri_log(7, "Timestamp set to %ld.%06ld\n", (long)tv.tv_sec, (long)tv.tv_usec);

    SCTime_t ts = SCTIME_FROM_TIMEVAL(&tv);

    SCPacketSetSource(p, PKT_SRC_WIRE);
    SCPacketSetTime(p, ts);

    // LINKTYPE_RAW (DLT_RAW): raw IP, no Ethernet header.
    // Because we are feeding LINKTYPE_RAW, Suricata expects the packet 
    // buffer data to immediately start with a valid IP header.
    SCPacketSetDatalink(p, LINKTYPE_RAW);

    // ATTENTION: Suricata does NOT detect unless we ignore checksums
    p->flags |= PKT_IGNORE_CHECKSUM;

    SCPacketSetLiveDevice(p, GetLiveDevice(req));
    SCPacketSetReleasePacket(p, ReleasePacket);

    // Use threadvars variable isolated strictly to this execution thread context
    if (TmThreadsSlotProcessPkt(my_tv, my_tv->tm_slots, p) != TM_ECODE_OK) {
        suri_log(1, "TmThreadsSlotProcessPkt failed\n");
        TmqhOutputPacketpool(my_tv, p);
        return -1;
    }

    int rv = 0;

    // QUERY VERDICT
    if (p->action & ACTION_DROP) {
        suri_log(1, "Action verdict MATCHED a blocking signature, drop reason: %s\n",
            PacketDropReasonToString(p->drop_reason));
        rv = 1;
    }

    LiveDevicePktsIncr(GetLiveDevice(req));

    // ATTENTION: Do not recycle the packet with thread-local TVs, it will be handled by the Suricata engine
    // TmqhOutputPacketpool(my_tv, p);
    return rv;
}

static void suri_cfg_set(ci_service_xdata_t *srv_xdata)
{
    if (SURI_BUFSIZE < SURI_PREVIEW) {
        suri_log(1, "Buffer size must be larger than or equal to preview size, exiting, bufsize=%u, preview=%u\n", SURI_BUFSIZE, SURI_PREVIEW);
        // c-icap does not exit if we return CI_ERROR from the init functions, so we must force exit here to prevent running with invalid config
        // Force c-icap's internal log buffers to dump to disk immediately
        fflush(NULL);
        exit(EXIT_FAILURE);
    }

    suri_log(7, "Set preview size, preview=%u <= bufsize=%u\n", SURI_PREVIEW, SURI_BUFSIZE);
    ci_service_set_preview(srv_xdata, SURI_PREVIEW);

    // Ask clients to send preview for all content types
    ci_service_set_transfer_preview(srv_xdata, "*");

    if (SURI_MODE == mode_allow204) {
        suri_log(7, "Enable 204 mode\n");
        ci_service_enable_204(srv_xdata);
    }
    else {
        suri_log(7, "Disable 204 mode\n");
        // c-icap does not provide a public API to clear the 204 feature flag, so we must do it manually here
        ci_thread_rwlock_wrlock(&srv_xdata->lock);
        srv_xdata->allow_204 = 0;
        ci_thread_rwlock_unlock(&srv_xdata->lock);
    }
}

/* Callback executed by c-icap inside commands_execute_start_child() */
static void suri_child_start_cmd_cb(const char *name, int type, void *data)
{
    pid_t current_pid = getpid();

    /* Initialize Suricata library and spin up threads here */
    suri_log(5, "Initializing Suricata inside child process (PID: %d)\n", current_pid);

    // Seed the generator for tcp seq numbers
    srandom(time(NULL));

    // SuricataPreInit must be the very first call.  We pass the service name
    // as argv[0] equivalent so Suricata can locate its own binary path.
    SuricataPreInit("srv_suricata");

    // Offline/library mode, no live capture device required
    SCRunmodeSet(RUNMODE_LIB);

    // Finalize runmode selection, required before SuricataInit
    if (SCFinalizeRunMode() != TM_ECODE_OK) {
        suri_log(1, "SCFinalizeRunMode failed\n");
        return;
    }

    // Register a virtual loopback "live" device for packets to be associated with
    if (LiveRegisterDevice("suri_icap0") < 0) {
        suri_log(1, "LiveRegisterDevice failed\n");
        return;
    }

    // Register our custom runmode with its setup callback
    RunModeRegisterNewRunMode(
        RUNMODE_LIB,
        "icap",
        "c-icap ICAP inspection runmode",
        SuricataRunModeSetup,
        NULL /* TODO: Need teardown callback */
    );

    // Tell Suricata to use our custom runmode
    if (!SCConfSet("runmode", "icap")) {
        suri_log(1, "SCConfSet runmode failed\n");
        return;
    }

    // Do not intercept c-icap signals
    // SCEnableDefaultSignalHandlers();

    // Load the config from file
    if (SCLoadYamlConfig() != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    // Set up a thread-local key configuration block before priming any threads
    if (pthread_key_create(&g_worker_tv_key, ThreadVarsDestroyCallback) != 0) {
        suri_log(1, "Critical Error: Failed to configure pthread TLS storage key variables.\n");
        return;
    }

    suri_log(7, "SuricataInit() (PID: %d)\n", current_pid);
    SuricataInit();

    SCDetectEngineRegisterRateFilterCallback(RateFilterCallback, NULL);

    // Start the dedicated worker thread BEFORE SuricataPostInit.
    // The worker calls SCRunModeLibSpawnWorker(g_worker_tv) which blocks inside
    // TmThreadsWaitForUnpause until SuricataPostInit -> TmThreadContinueThreads
    // clears THV_PAUSE.  Do NOT call GetThreadWorkerVars() here (init thread) --
    // that would register an extra TV that never gets SCRunModeLibSpawnWorker
    // called on it, causing TmThreadWaitOnThreadInit to time out after 120s.
    if (pthread_create(&g_worker_thread_id, NULL, SuricataWorkerThread, NULL) != 0) {
        suri_log(1, "pthread_create for worker failed, failed to initialize Suricata\n");
        return;
    }

    // Post-init seals threads, starts packet queues, etc.
    suri_log(7, "SuricataPostInit() (PID: %d)\n", current_pid);
    SuricataPostInit();

    suri_log(5, "Suricata engine ready (PID: %d)\n", current_pid);
    g_suri_ready = 1;
}

// Called once when the module is loaded
int suri_init_service(ci_service_xdata_t *srv_xdata, struct ci_server_conf *server_conf)
{
    // We init Suricata in suri_child_start_cmd_cb, so nothing to do here
    suri_log(5, "ENTER\n");
    return CI_OK;
}

int suri_post_init_service(ci_service_xdata_t * srv_xdata, struct ci_server_conf *server_conf)
{
    // We init Suricata in suri_child_start_cmd_cb, so nothing else to do here
    suri_log(5, "ENTER\n");

    // Record the exact PID that initialized the engine,
    // so we can conditionally stop engine in child processes.
    g_parent_pid = getpid();

    // Set config again, with possibly updated values
    // Note that suri_cfg_set is specified in ci_service_module_t,
    // hence is called first during service init
    suri_cfg_set(srv_xdata);

    // Register the start command handler with c-icap for child processes to init Suricata
    suri_log(5, "Register suri_child_start command\n");
    ci_command_register_action("suri_child_start", CI_CMD_CHILD_START, NULL, suri_child_start_cmd_cb);

    suri_log(7, "EXIT\n");
    return CI_OK;
}

// Called when c-icap shuts down
void suri_close_service(void)
{
    pid_t current_pid = getpid();
    suri_log(5, "ENTER, g_suri_ready=%d, g_parent_pid=%d, current_pid=%d\n", g_suri_ready, g_parent_pid, current_pid);

    if (current_pid == g_parent_pid) {
        // ATTENTION: We don't call EngineStop() for parent, as parent does not have a worker loop.
        // suri_log(7, "EngineStop()\n");
        // EngineStop();                             /* Tell worker loop to stop */

        // ATTENTION: We don't call SuricataShutdown() here, parent never calls SuricataPostInit().
        // Otherwise, SuricataShutdown() hangs.
        // suri_log(7, "SuricataShutdown()\n");
        // SuricataShutdown();

        // ATTENTION: We don't call GlobalsDestroy() for parent, as parent does not call SuricataInit().
        // suri_log(7, "GlobalsDestroy()\n");
        // GlobalsDestroy();

        suri_log(5, "Parent shutdown complete, current_pid=%d\n", current_pid);

        // ATTENTION: Never use _exit() here, otherwise the other services managed by c-icap may not get a chance to clean up properly.
        // _exit(0);
        return;
    }

    if (!g_suri_ready) {
        suri_log(7, "Suricata not ready in child process, skipping shutdown, current_pid=%d\n", current_pid);
        return;
    }
    g_suri_ready = 0;

    // ATTENTION: Only tear down threads and force exit if we are running 
    // inside the specific process context that initialized them.
    suri_log(7, "Suricata shutdown in child process, current_pid=%d\n", current_pid);

    if (g_worker_thread_id > 0) {
        suri_log(7, "EngineStop()\n");
        EngineStop();                             /* Tell worker loop to stop */

        // ATTENTION: We don't call SuricataShutdown() here, as EngineStop() is enough for a clean shutdown.
        // Otherwise, SuricataShutdown() hangs.
        // suri_log(7, "SuricataShutdown()\n");
        // SuricataShutdown();

        // ATTENTION: We don't call SCTmThreadsSlotPacketLoopFinish() here for bootstrap or lazy TVs.
        // suri_log(5, "SCTmThreadsSlotPacketLoopFinish() for bootstrap TV\n");
        // SCTmThreadsSlotPacketLoopFinish(g_worker_tv);
        // for (int i = 0; i < count; i++) {
        //     suri_log(5, "SCTmThreadsSlotPacketLoopFinish() for lazy TV %d, g_lazy_tvs[i]->id=%d\n", i, g_lazy_tvs[i]->id);
        //     SCTmThreadsSlotPacketLoopFinish(g_lazy_tvs[i]);
        // }

        /* Clean up and UNLINK all lazy TVs */
        pthread_mutex_lock(&g_lazy_tv_lock);
        for (int i = 0; i < g_lazy_tv_count; i++) {
            if (g_lazy_tvs[i] != NULL) {
                suri_log(7, "Child unlinking and freeing lazy TV [%s]\n", g_lazy_tvs[i]->name);
                suri_free_tv(g_lazy_tvs[i]);
                g_lazy_tvs[i] = NULL;
            }
        }
        g_lazy_tv_count = 0;
        pthread_mutex_unlock(&g_lazy_tv_lock);

        // ATTENTION: We kill/join Suricata management threads, otherwise c-icap segfaults
        /* Traverse ALL linked lists across all TVT types */
        SCMutexLock(&tv_root_lock);
        for (int i = 0; i < TVT_MAX; i++) {
            ThreadVars *tv = tv_root[i];
            while (tv != NULL) {
                /* Store next pointer before canceling/joining, as joining may free tv */
                ThreadVars *next_tv = tv->next;

                if (tv->t != 0) {
                    if (!pthread_equal(tv->t, pthread_self())) {
                        suri_log(7, "Child canceling Suricata thread [%s, %d, %d] (ID: %lu)\n",
                            tv->name, tv->id, tv->type, (unsigned long)tv->t);

                        /* Force pthread to cancel immediately */
                        pthread_cancel(tv->t);

                        /* Wait for thread to actually terminate */
                        pthread_join(tv->t, NULL);
                    }
                    else {
                        suri_log(7, "Child skipping cancellation of (self) thread [%s, %d, %d] (ID: %lu)\n",
                            tv->name, tv->id, tv->type, (unsigned long)tv->t);
                    }
                }
                else {
                    suri_log(7, "Child skipping cancellation of (no thread) thread [%s, %d, %d] (ID: %lu)\n",
                        tv->name, tv->id, tv->type, (unsigned long)tv->t);
                }

                tv = next_tv;
            }
        }
        SCMutexUnlock(&tv_root_lock);

#ifdef __linux__
        pid_t tid = syscall(SYS_gettid);
#else
        pid_t tid = getthrid();
#endif
        // The pthread_join here ensures the worker has finished before we return.
        suri_log(7, "Child joining worker thread, g_worker_thread_id=%llu, tid=%d\n", (unsigned long long)g_worker_thread_id, tid);
        pthread_join(g_worker_thread_id, NULL);

        // Clean up and UNLINK the bootstrap TV (g_worker_tv / W#01)
        suri_log(7, "Unlink and free bootstrap TV [%s]\n", g_worker_tv->name);
        suri_free_tv(g_worker_tv);
        g_worker_tv = NULL;

        suri_log(7, "GlobalsDestroy()\n");
        GlobalsDestroy();

        suri_log(5, "Child shutdown complete, current_pid=%d\n", current_pid);
    } else {
        suri_log(7, "Child has no worker thread to join\n");
    }
}

void *suri_init_request_data(ci_request_t *req)
{
    suri_log(1, "ENTER\n");

    if (!g_suri_ready) {
        suri_log(1, "Suricata not initialized (PID: %d)\n", getpid());
        return NULL;
    }

    struct suri_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        suri_log(1, "calloc failed for request data\n");
        return NULL;
    }

    if (ci_req_hasbody(req)) {
        ctx->body_buf = dual_ring_buf_create(SURI_BUFSIZE);
        if (!ctx->body_buf) {
            suri_log(1, "body_buf init failed\n");
            free(ctx);
            return NULL;
        }
    }

    return ctx;
}

void suri_release_request_data(void *data)
{
    suri_log(5, "ENTER\n");

    struct suri_ctx *ctx = (struct suri_ctx *)data;
    if (!ctx)
        return;

    suri_log(5, "cap=%zu, client_len=%zu, suri_len=%zu\n",
        ctx->body_buf ? ctx->body_buf->capacity : 0,
        ctx->body_buf ? dual_ring_buf_client_read_available(ctx->body_buf) : 0,
        ctx->body_buf ? dual_ring_buf_suri_read_available(ctx->body_buf) : 0);

    if (ctx->body_buf) {
        dual_ring_buf_destroy(ctx->body_buf);
    }
    free(ctx);
}

static int suri_get_response_vars(ci_request_t *req)
{
    struct suri_ctx *ctx = ci_service_data(req);

    const char *vars = ci_icap_request_get_header(req, "X-Response-Vars");
    if (vars == NULL) {
        suri_log(7, "No X-Response-Vars\n");
        return 1;
    }

    char *v = strdup(vars);
    if (!v) {
        suri_log(1, "strdup for X-Response-Vars failed\n");
        return -1;
    }

    int rv = 0;
    char *comma = strchr(v, ',');
    if (comma) {
        comma[0] = '\0';

        char *endptr;
        unsigned long val = strtoul(v, &endptr, 10);
        if (endptr != v && *endptr == '\0' && val < 4294967296) {
            ctx->client_seq = val;
        }
        else {
            suri_log(7, "Invalid X-Response-Vars format %s\n", vars);
            rv = 1;
        }

        val = strtoul(comma + 1, &endptr, 10);
        if (endptr != comma + 1 && *endptr == '\0' && val < 4294967296) {
            ctx->server_seq = val;
        }
        else {
            suri_log(7, "Invalid X-Response-Vars format %s\n", vars);
            rv = 1;
        }
    }
    else {
        suri_log(7, "Invalid X-Response-Vars format %s\n", vars);
        rv = 1;
    }

    free(v);
    return rv;
}

static void suri_init_tcp_session(struct suri_ctx *ctx)
{
    // Open the kernel's secure random device
    // O_CLOEXEC is a good habit to prevent descriptor leaks with fork+exec, even though we don't exec here.
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        suri_log(1, "Failed to open /dev/urandom\n");
        goto err;
    }

    // Read raw, unpredictable bytes directly into the sequence variables
    size_t total_bytes = sizeof(ctx->client_seq) + sizeof(ctx->server_seq);
    uint32_t buffer[2];

    ssize_t bytes_read = read(fd, buffer, total_bytes);
    close(fd);

    if (bytes_read != (ssize_t)total_bytes) {
        suri_log(1, "Failed to read enough bytes from /dev/urandom\n");
        goto err;
    }

    // Assign the secure random numbers
    ctx->client_seq = buffer[0];
    ctx->server_seq = buffer[1];
    goto out;
err:
    // Generate valid random uint32_t values across the full 32-bit range
    suri_log(1, "Generating fallback random values\n");
    ctx->client_seq = (uint32_t)random();
    ctx->server_seq = (uint32_t)random();
out:
    ctx->client_ack = 0;
    ctx->server_ack = 0;
}

static int suri_set_seq_numbers(ci_request_t *req)
{
    struct suri_ctx *ctx = ci_service_data(req);

    if (req->type == ICAP_REQMOD) {
        suri_init_tcp_session(ctx);
    }
    else {
        // For response, we assume the connection is already established
        ctx->state = ESTABLISHED;

        int result = 0;
        if ((result = suri_get_response_vars(req)) == -1) {
            return -1;
        } else if (result == 1) {
            suri_log(7, "No or invalid X-Response-Vars, using random seq nums\n");
            // Suricata does NOT detect with these fallback values, it requires the actual seq nums from reqmod
            // but we will continue with these defaults if X-Response-Vars is not provided or has invalid format
            suri_init_tcp_session(ctx);
        }

        ctx->client_ack = ctx->server_seq;
        ctx->server_ack = ctx->client_seq;
    }

    suri_log(7, "Set client_seq=%u, server_seq=%u\n", ctx->client_seq, ctx->server_seq);
    return 0;
}

static int suri_handle_inspect_result(ci_request_t *req, int rv)
{
    struct suri_ctx *ctx = ci_service_data(req);

    // Avoid duplicate xheaders
    const char *xheader = NULL;

    switch (rv) {
    case 1:
        suri_log(5, "InjectPacket returned block\n");
        if (req->xheaders) {
            xheader = ci_headers_value(req->xheaders, "X-Response-Info");
        }
        if (!xheader || strcasecmp(xheader, "blocked") != 0) {
            ci_icap_add_xheader(req, "X-Response-Info: blocked");
        }
        else {
            suri_log(5, "X-Response-Info already set to blocked\n");
        }
        ctx->block = 1;
        break;
    case 0:
        suri_log(5, "InjectPacket did not return block, continue processing\n");
        if (req->xheaders) {
            xheader = ci_headers_value(req->xheaders, "X-Response-Info");
        }
        if (!xheader || strcasecmp(xheader, "continue") != 0) {
            ci_icap_add_xheader(req, "X-Response-Info: continue");
        }
        else {
            suri_log(5, "X-Response-Info already set to continue\n");
        }

        // Seq numbers are passed from reqmod to respmod, do not send them in respmod
        if (req->type == ICAP_RESPMOD) {
            break;
        }

        if (req->xheaders && ci_headers_value(req->xheaders, "X-Response-Vars")) {
            suri_log(5, "X-Response-Vars already set\n");
            break;
        }

        char resp_vars[64];
        if (snprintf(resp_vars, sizeof(resp_vars), "X-Response-Vars: %u,%u", ctx->client_seq, ctx->server_seq) >= 0) {
            suri_log(7, "Injecting: %s\n", resp_vars);
            ci_icap_add_xheader(req, resp_vars);
            break;
        }
        suri_log(1, "snprintf failed\n");
        // fall through to error handling
    case -1:
        suri_log(1, "InjectPacket failed\n");
        if (req->xheaders) {
            xheader = ci_headers_value(req->xheaders, "X-Response-Info");
        }
        if (!xheader || strcasecmp(xheader, "error") != 0) {
            ci_icap_add_xheader(req, "X-Response-Info: error");
        }
        else {
            suri_log(5, "X-Response-Info already set to error\n");
        }
        ctx->error = 1;
        return CI_MOD_ERROR;
    default:
        suri_log(7, "Did not inject packet or changed state\n");
        break;
    }

    return CI_MOD_DONE;
}

int suri_check_preview_handler(char *preview_data, int preview_data_len, ci_request_t *req)
{
    ci_off_t content_len;

    struct suri_ctx *ctx = ci_service_data(req);

    content_len = ci_http_content_length(req);
    suri_log(9, "We expect to read :%" PRINTF_OFF_T " body data\n", (CAST_OFF_T) content_len);

    ci_req_unlock_data(req);

    // Set to -2 to distinguish uninitialized state
    int rv = -2;

    if (preview_data_len > (int)SURI_PREVIEW) {
        suri_log(1, "Preview data len larger than preview size configured, preview_data_len=%d, preview size=%d\n", preview_data_len, SURI_PREVIEW);
        rv = -1;
        goto out;
    }
    else if (preview_data_len == 0) {
        suri_log(9, "No preview data received, continue processing\n");
        // We send http headers in preview handler, not just body
        // return CI_MOD_CONTINUE;
    }

    suri_log(7, "Injecting %d bytes into Suricata\n", preview_data_len);

    if (suri_set_seq_numbers(req) == -1) {
        rv = -1;
        goto out;
    }

    if (req->type == ICAP_REQMOD) {
        // TCP handshake
        suri_log(7, "Inject SYN packet\n");
        if ((rv = InjectPacket(req, NULL, 0, TH_SYN, 1)) != 0) {
            goto out;
        }
    
        suri_log(7, "Inject SYN|ACK packet\n");
        if ((rv = InjectPacket(req, NULL, 0, TH_SYN|TH_ACK, 0)) != 0) {
            goto out;
        }

        suri_log(7, "Inject ACK packet\n");
        if ((rv = InjectPacket(req, NULL, 0, TH_ACK, 1)) != 0) {
            goto out;
        }
    }

    size_t http_headers_len = 0;
    char http_headers[SURI_MAX_HTTP_HDRS];

    ci_headers_list_t *http_headers_list = req->type == ICAP_REQMOD ? ci_http_request_headers(req) : ci_http_response_headers(req);
    if (http_headers_list) {
        http_headers_len = ci_headers_pack_to_buffer(http_headers_list, http_headers, sizeof(http_headers));
        if (http_headers_len == 0) {
            suri_log(1, "HTTP headers do not fit to buffer\n");
            rv = -1;
            goto out;
        }
    } else {
        // TODO: Is this an error? But we will support protocols other than HTTP
        suri_log(3, "http_headers_list is NULL\n");
    }

    size_t payload_len = http_headers_len + preview_data_len;
    char *payload = malloc(payload_len);
    if (!payload) {
        suri_log(1, "malloc failed for combined buffer\n");
        rv = -1;
        goto out;
    }

    // Noop if http_headers_len is 0
    memcpy(payload, http_headers, http_headers_len);
    if (preview_data && preview_data_len > 0) {
        memcpy(payload + http_headers_len, preview_data, preview_data_len);
    }

    if (payload_len > 0) {
        suri_log(5, "Injecting %zu bytes into Suricata, http_headers_len=%zu, preview_data_len=%d\n",
            payload_len, http_headers_len, preview_data_len);

        if ((rv = InjectPacket(req, payload, payload_len, TH_PUSH|TH_ACK, req->type == ICAP_REQMOD ? 1 : 0)) != 0) {
            goto out;
        }

        if (!StreamTcpInlineMode() && SURI_ACKWINDOW > 0) {
            ctx->injected_since_ack = preview_data_len;

            // ATTENTION: In IDS mode Suricata does not detect unless we also inject these final ACK packets to flush the flow
            suri_log(7, "Inject ACK packet to %s for flushing\n", req->type == ICAP_REQMOD ? "client" : "server");
            if ((rv = InjectPacket(req, NULL, 0, TH_ACK, req->type == ICAP_REQMOD ? 0 : 1)) != 0) {
                goto out;
            }

            suri_log(7, "Inject ACK packet to %s for flushing\n", req->type == ICAP_REQMOD ? "server" : "client");
            if ((rv = InjectPacket(req, NULL, 0, TH_ACK, req->type == ICAP_REQMOD ? 1 : 0)) != 0) {
                goto out;
            }
        }
    }
out:
    // Silence the warning: label followed by a declaration is a C23 extension
    ;
    int result = suri_handle_inspect_result(req, rv);

    if (rv == 1) {
        // ATTENTION: We set X-Response-Info for the 204 response, but c-icap does not send any headers with 100 Continue
        // If we return CI_MOD_DONE, c-icap sends 500 Error to the client
        return SURI_MODE == mode_allow204 ? CI_MOD_ALLOW204 : CI_MOD_CONTINUE;
    }

    if (result == CI_MOD_ERROR) {
        return CI_MOD_ERROR;
    }

    if (ci_req_hasalldata(req)) {
        suri_log(7, "All data received in preview\n");
    }

    if (preview_data && preview_data_len > 0) {
        suri_log(5, "Buffer preview data, preview_data_len=%d\n", preview_data_len);
        int written = dual_ring_buf_write(ctx->body_buf, preview_data, preview_data_len);
        if (written < preview_data_len) {
            suri_log(1, "Failed to write to body_buf, written=%d < preview_data_len=%d\n", written, preview_data_len);
            return CI_MOD_ERROR;
        }

        // Advance the suri read pointer since we have already injected the preview data, no memcpy
        dual_ring_buf_suri_read(ctx->body_buf, NULL, preview_data_len);
    }

    return CI_MOD_CONTINUE;
}

int suri_end_of_data_handler(ci_request_t *req)
{
    struct suri_ctx *ctx = ci_service_data(req);

    int inject_len = ctx->body_buf ? dual_ring_buf_suri_read_available(ctx->body_buf) : 0;
    suri_log(5, "ENTER, body_len=%d, block=%d, error=%d, eof=%d\n", inject_len, ctx->block, ctx->error, ctx->eof);

    // Set to -2 to distinguish uninitialized state
    int rv = -2;

    // Only inject if we haven't already done so in the preview handler or io callback
    if (!ctx->block && !ctx->error && !ctx->eof && inject_len > 0) {
        suri_log(5, "Injecting %d bytes into Suricata\n", inject_len);
        char inject_buf[inject_len];
        inject_len = dual_ring_buf_suri_read(ctx->body_buf, inject_buf, inject_len);

        if ((rv = InjectPacket(req, inject_buf, inject_len, TH_PUSH|TH_ACK, req->type == ICAP_REQMOD ? 1 : 0)) != 0) {
            goto out;
        }
    }

    // Do not inject FIN packets if already blocked, as Suricata returns "flow drop" once it has marked a flow as dropped
    if ((req->type != ICAP_REQMOD || ctx->error) && !ctx->block && ctx->state != FIN) {
        ctx->state = FIN;

        suri_log(7, "Inject FIN|ACK packet to server\n");
        if ((rv = InjectPacket(req, NULL, 0, TH_FIN|TH_ACK, 1)) != 0) {
            goto out;
        }

        suri_log(7, "Inject FIN|ACK packet to client\n");
        if ((rv = InjectPacket(req, NULL, 0, TH_FIN|TH_ACK, 0)) != 0) {
            goto out;
        }
    }
out:
    ctx->eof = 1;
    return suri_handle_inspect_result(req, rv);
}

int suri_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof, ci_request_t *req)
{
    struct suri_ctx *ctx = ci_service_data(req);

    suri_log(5, "ENTER rbuf=%p, wbuf=%p, rlen=%p, wlen=%p, *rlen=%d, *wlen=%d, iseof=%d, req=%p\n",
        rbuf, wbuf, rlen, wlen, rlen ? *rlen : 0, wlen ? *wlen : 0, iseof, req);

    if (ctx->block || ctx->error) {
        suri_log(5, "Skip data, block=%d, eof=%d, error=%d\n", ctx->block, ctx->eof, ctx->error);
        if (wlen) {
            suri_log(5, "Set EOF\n");
            *wlen = CI_EOF;
        }
        return CI_MOD_DONE;
    }

    // Set to -2 to distinguish uninitialized state
    int rv = -2;

    if (rbuf && rlen && *rlen > 0) {
        suri_log(5, "Buffer incoming data, rlen=%d\n", *rlen);
        int written = dual_ring_buf_write(ctx->body_buf, rbuf, *rlen);
        if (written < *rlen) {
            suri_log(1, "Failed to write to body_buf, written=%d < rlen=%d\n", written, *rlen);
        }
        // Tell c-icap that we consumed some or all of the rbuf data
        *rlen = written;
    }

    if (wbuf && wlen && *wlen > 0) {
        int body_buf_copy_len = dual_ring_buf_client_read_available(ctx->body_buf);

        if (body_buf_copy_len > 0) {
            body_buf_copy_len = body_buf_copy_len < *wlen ? body_buf_copy_len : *wlen;

            suri_log(5, "Send %d bytes from body_buf to client\n", body_buf_copy_len);
            int written = dual_ring_buf_client_read(ctx->body_buf, wbuf, body_buf_copy_len);
            if (written < body_buf_copy_len) {
                suri_log(1, "Failed to write to wbuf, written=%d < body_buf_copy_len=%d\n", written, body_buf_copy_len);
            }
            body_buf_copy_len = written;
        }
        // Tell c-icap how many bytes we have written to wbuf to be sent to the client
        // This sets *wlen to 0 if we have no data to send, so we can set *wlen to CI_EOF below if iseof
        *wlen = body_buf_copy_len;
    }

    // suri_check_preview_handler() advances the suri read pointer for the preview data
    int inject_len = dual_ring_buf_suri_read_available(ctx->body_buf);

    // suri_end_of_data_handler() consumes all remaining data after the suri read pointer
    if (inject_len > 0 &&  ctx->state != FIN) {
        char inject_buf[inject_len];
        dual_ring_buf_suri_read(ctx->body_buf, inject_buf, inject_len);

        if (!StreamTcpInlineMode() && SURI_ACKWINDOW > 0) {
            ctx->injected_since_ack += inject_len;
        }

        suri_log(5, "Injecting %d bytes into Suricata\n", inject_len);
        if ((rv = InjectPacket(req, inject_buf, inject_len, TH_PUSH|TH_ACK, req->type == ICAP_REQMOD ? 1 : 0)) != 0) {
            *wlen = 0;  // Tell c-icap not to send wbuf to the client
            goto out;
        }
    }

    int client_avail = dual_ring_buf_client_read_available(ctx->body_buf);
    suri_log(5, "Current *rlen=%d, *wlen=%d, client_avail=%d, inject_len=%d\n", rlen ? *rlen : 0, wlen ? *wlen : 0, client_avail, inject_len);

    if (wlen && *wlen == 0 && (ctx->eof == 1 || iseof) && client_avail == 0) {
        suri_log(5, "Set EOF\n");
        *wlen = CI_EOF;
    }

    if (!StreamTcpInlineMode() && SURI_ACKWINDOW > 0) {
        // This io function may be called after end_of_data_handler and when we set CI_EOF above,
        // so do not inject duplicate ACK packets, hence ctx->state != FIN and ctx->injected_since_ack > 0
        if ((ctx->injected_since_ack >= SURI_ACKWINDOW || (iseof && ctx->injected_since_ack > 0)) && ctx->state != FIN) {
            suri_log(7, "Reached ACK window size or iseof, injecting ACK packets, injected_since_ack=%u, ACKWINDOW=%u, iseof=%d, state=%d\n",
                ctx->injected_since_ack, SURI_ACKWINDOW, iseof, ctx->state);

            ctx->injected_since_ack = 0;

            // ATTENTION: In IDS mode Suricata does not detect unless we also inject these final ACK packets to flush the flow
            suri_log(7, "Inject ACK packet to %s for flushing\n", req->type == ICAP_REQMOD ? "client" : "server");
            if ((rv = InjectPacket(req, NULL, 0, TH_ACK, req->type == ICAP_REQMOD ? 0 : 1)) != 0) {
                *wlen = 0;  // Tell c-icap not to send wbuf to the client
                goto out;
            }

            suri_log(7, "Inject ACK packet to %s for flushing\n", req->type == ICAP_REQMOD ? "server" : "client");
            if ((rv = InjectPacket(req, NULL, 0, TH_ACK, req->type == ICAP_REQMOD ? 1 : 0)) != 0) {
                *wlen = 0;  // Tell c-icap not to send wbuf to the client
                goto out;
            }
        }
    }
out:
    // Silence the warning: label followed by a declaration is a C23 extension
    ;
    int result = suri_handle_inspect_result(req, rv);
    if (result == CI_MOD_DONE && (rv == 0 || rv == -2)) {
        return CI_OK;
    }
    return result;
}

static int suri_cfg_mode(const char *directive, const char **argv, void *setdata)
{
    if (strcasecmp(argv[0], "allow204") == 0) {
        SURI_MODE = mode_allow204;
    }
    else if (strcasecmp(argv[0], "disallow204") == 0) {
        SURI_MODE = mode_disallow204;
    }
    else {
        suri_log(1, "Unknown value '%s' for configuration parameter '%s'\n", argv[0], directive);
        return 0;
    }
    suri_log(2, "Setting parameter: %s\n", directive);
    return 1;
}

static int suri_cfg_ackwindow(const char *directive, const char **argv, void *setdata)
{
    if (argv == NULL || argv[0] == NULL) {
        suri_log(1, "Missing arguments in directive %s \n", directive);
        return 0;
    }

    errno = 0;
    char *endptr;
    unsigned long size = strtoul(argv[0], &endptr, 10);
    if (errno != 0 || endptr == argv[0] || *endptr != '\0' || size > 65535) {
        suri_log(1, "Invalid argument in directive %s \n", directive);
        return 0;
    }

    if (StreamTcpInlineMode() && size > 0) {
        suri_log(1, "ACKwindow enabled in TCP stream inline mode\n");
        return 0;
    }

    suri_log(2, "Setting parameter: %s=%lu\n", directive, size);
    SURI_ACKWINDOW = size;
    return 1;
}

static int suri_cfg_preview(const char *directive, const char **argv, void *setdata)
{
    if (argv == NULL || argv[0] == NULL) {
        suri_log(1, "Missing arguments in directive %s \n", directive);
        return 0;
    }

    errno = 0;
    char *endptr;
    unsigned long size = strtoul(argv[0], &endptr, 10);
    if (errno != 0 || endptr == argv[0] || *endptr != '\0' || size > 65535) {
        suri_log(1, "Invalid argument in directive %s \n", directive);
        return 0;
    }

    suri_log(2, "Setting parameter: %s=%lu\n", directive, size);
    SURI_PREVIEW = size;
    return 1;
}

static int suri_cfg_bufsize(const char *directive, const char **argv, void *setdata)
{
    if (argv == NULL || argv[0] == NULL) {
        suri_log(1, "Missing arguments in directive %s \n", directive);
        return 0;
    }

    errno = 0;
    char *endptr;
    unsigned long size = strtoul(argv[0], &endptr, 10);
    // 4 MiB max buffer size, arbitrary limit to prevent excessive memory usage
    if (errno != 0 || endptr == argv[0] || *endptr != '\0' || size > 4194304) {
        suri_log(1, "Invalid argument in directive %s \n", directive);
        return 0;
    }

    suri_log(2, "Setting parameter: %s=%lu\n", directive, size);
    SURI_BUFSIZE = size;
    return 1;
}
