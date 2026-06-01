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
#include <c-icap/c-icap.h>
#include <c-icap/service.h>
#include <c-icap/header.h>
#include <c-icap/body.h>
#include <c-icap/simple_api.h>
#include <c-icap/debug.h>
#include <c-icap/cfg_param.h>

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

#define SRV_SURICATA_INIT_BODY_BUF_SIZE (16 * 1024)  /* 16 KiB */
#define SRV_SURICATA_MAX_HTTP_HDRS (16 * 1024)  /* 16 KiB */

#define suri_log(LEVEL, format_str, ...) ci_debug_printf(LEVEL, "srv_suricata: %s: " format_str, __FUNCTION__, ##__VA_ARGS__)

static ThreadVars *g_worker_tv  = NULL;
static pthread_t   g_worker_tid = 0;
static int         g_suri_ready = 0;   /* set to 1 after SuricataPostInit */
static pid_t       g_parent_pid = 0;   /* Tracks which process initialized Suricata */

enum conn_state {
    SYN = 0,
    SYN_ACK,
    ACK,
    ESTABLISHED,
    FIN
};

typedef struct {
    char *buffer;
    size_t capacity;       // Total size of the allocated ring array
    size_t write_ptr;      // Where new data from c-icap goes
    size_t read_client_ptr;// Tracking index for data sent to client
    size_t read_suri_ptr;  // Tracking index for data injected to Suricata
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

// Per-request data structure
struct suri_req_ctx {
    dual_ring_buf_t *body_buf;       /* accumulation buffer */
    unsigned int preview_injected;   /* preview injected to Suricata */
    unsigned int injected_since_ack; /* bytes injected to Suricata since last ACK */

    unsigned int eof : 1;
    unsigned int block : 1;
    unsigned int error : 1;
    unsigned int sent_fin : 1;

    uint32_t client_ip;
    unsigned int client_ip_set : 1;
    uint16_t client_port;
    unsigned int client_port_set : 1;
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
    enum conn_state state;

    // __suseconds_t tv_usec;
};

enum suri_mode {mode_disallow204, mode_allow204};
static int MODE = mode_allow204;

// The c-icap wbuf size is usually 4064 bytes, so pick a threshold slightly below that
// Setting ACKWINDOW to 0 disables ACK injection
static unsigned int ACKWINDOW = 4000;  /* bytes */

static int  suri_cfg_mode(const char *directive, const char **argv, void *setdata);
static int  suri_cfg_ackwindow(const char *directive, const char **argv, void *setdata);
static struct ci_conf_entry suri_conf_variables[] = {
    {"Mode", NULL, suri_cfg_mode, NULL},
    {"ACKwindow", NULL, suri_cfg_ackwindow, NULL},
};

int  suri_init_service(ci_service_xdata_t *srv_xdata, struct ci_server_conf *server_conf);
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
    NULL,                               /* post_init_service         */
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

// The library runmode needs at least one ThreadVars created in a runmode-setup
// callback before SuricataInit seals the threads.
static int SuricataRunModeSetup(void)
{
    suri_log(9, "ENTER\n");

    // TimeModeSetOffline: we feed synthetic packets with fabricated timestamps,
    // so we do not want the engine to complain about clock skew.
    TimeModeSetOffline();

    g_worker_tv = SCRunModeLibCreateThreadVars(1 /* worker_id */);
    if (g_worker_tv == NULL) {
        suri_log(1, "SCRunModeLibCreateThreadVars failed\n");
        return -1;
    }
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

// Worker thread body: keeps the Suricata slot loop alive so that packets we
// inject via TmThreadsSlotProcessPkt() are actually processed.
// Here we simply block inside SuricataMainLoop which returns only when the
// engine is stopped.
static void *SuricataWorkerThread(void *arg)
{
    (void)arg;

    suri_log(9, "ENTER\n");

    if (SCRunModeLibSpawnWorker(g_worker_tv) != 0) {
        suri_log(1, "SCRunModeLibSpawnWorker failed\n");
        pthread_exit((void *)(intptr_t)EXIT_FAILURE);
    }

    suri_log(5, "SuricataMainLoop()\n");
    SuricataMainLoop();

    // Note that there is some thread synchronization between this
    // function and SuricataShutdown such that they must be run
    // concurrently at this time before either will exit.
    if (g_worker_tv != NULL) {
        suri_log(5, "SCTmThreadsSlotPacketLoopFinish()\n");
        SCTmThreadsSlotPacketLoopFinish(g_worker_tv);
    }

    suri_log(5, "EXIT\n");
    pthread_exit((void *)(intptr_t)EXIT_SUCCESS);
}

// Minimal 40-byte raw Layer 3 / Layer 4 structure 
// packed to ensure precise network formatting alignment.
struct __attribute__((__packed__)) fake_pkt_hdr {
    struct iphdr ip;
    struct tcphdr tcp;
};

static uint32_t GetClientIP(ci_request_t *req)
{
    struct suri_req_ctx *ctx = ci_service_data(req);
    suri_log(9, "X-Client-IP=%s\n", ci_icap_request_get_header(req, "X-Client-IP"));

    if (!ctx->client_ip_set) {
        ctx->client_ip = htonl(0x7F000001);  /* Fallback to 127.0.0.1 */
        ctx->client_ip_set = 1;

        const char *ip_str = ci_icap_request_get_header(req, "X-Client-IP");
        if (ip_str) {
            inet_pton(AF_INET, ip_str, &ctx->client_ip);
        }
    }

    return ctx->client_ip;
}

static uint32_t GetClientPort(ci_request_t *req)
{
    struct suri_req_ctx *ctx = ci_service_data(req);
    suri_log(9, "X-Client-Port=%s\n", ci_icap_request_get_header(req, "X-Client-Port"));

    if (!ctx->client_port_set) {
        ctx->client_port = htons(12345);  /* Fallback to 12345 */
        ctx->client_port_set = 1;

        const char *port_str = ci_icap_request_get_header(req, "X-Client-Port");
        if (port_str) {
            ctx->client_port = htons(atoi(port_str));
        }
    }

    return ctx->client_port;
}

static uint32_t GetServerIP(ci_request_t *req)
{
    struct suri_req_ctx *ctx = ci_service_data(req);
    suri_log(9, "X-Server-IP=%s\n", ci_icap_request_get_header(req, "X-Server-IP"));

    if (!ctx->server_ip_set) {
        ctx->server_ip = htonl(0x7F000001);  /* Fallback to 127.0.0.1 */
        ctx->server_ip_set = 1;

        const char *ip_str = ci_icap_request_get_header(req, "X-Server-IP");
        if (ip_str) {
            inet_pton(AF_INET, ip_str, &ctx->server_ip);
        }
    }

    return ctx->server_ip;
}

static uint32_t GetServerPort(ci_request_t *req)
{
    struct suri_req_ctx *ctx = ci_service_data(req);
    suri_log(9, "X-Server-Port=%s\n", ci_icap_request_get_header(req, "X-Server-Port"));

    if (!ctx->server_port_set) {
        ctx->server_port = htons(80);  /* Fallback to 80 */
        ctx->server_port_set = 1;

        const char *port_str = ci_icap_request_get_header(req, "X-Server-Port");
        if (port_str) {
            ctx->server_port = htons(atoi(port_str));
        }
    }

    return ctx->server_port;
}

static uint8_t GetProto(ci_request_t *req)
{
    struct suri_req_ctx *ctx = ci_service_data(req);
    suri_log(9, "X-Proto=%s\n", ci_icap_request_get_header(req, "X-Proto"));

    if (!ctx->proto_set) {
        ctx->proto = IPPROTO_TCP;     /* Default to TCP */
        ctx->proto_set = 1;

        const char *proto_str = ci_icap_request_get_header(req, "X-Proto");
        if (proto_str && strcasecmp(proto_str, "UDP") == 0) {
            ctx->proto = IPPROTO_UDP;
        }
    }

    return ctx->proto;
}

static LiveDevice *GetLiveDevice(ci_request_t *req)
{
    struct suri_req_ctx *ctx = ci_service_data(req);

    if (!ctx->dev_set) {
        ctx->dev_set = 1;

        ctx->dev = LiveGetDevice("suri_icap0");
        if (ctx->dev == NULL) {
            suri_log(1, "LiveGetDevice failed\n");
        }
        else {
            suri_log(5, "Obtained LiveDevice for injection\n");
        }
    }

    return ctx->dev;
}

static void GetSeqAck(ci_request_t *req, size_t len, int toserver)
{
    struct suri_req_ctx *ctx = ci_service_data(req);

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
    struct suri_req_ctx *ctx = ci_service_data(req);

    size_t header_len = sizeof(struct fake_pkt_hdr);
    *pkt_len = header_len + data_len;

    uint8_t *pkt = malloc(*pkt_len);
    if (pkt == NULL) {
        suri_log(1, "malloc failed for pkt\n");
        return NULL;
    }

    struct fake_pkt_hdr *hdr = (struct fake_pkt_hdr *)pkt;
    memset(hdr, 0, header_len);

    hdr->ip.version = 4;
    hdr->ip.ihl = 5;                        /* 5 dwords = 20 bytes */
    hdr->ip.tot_len = htons(*pkt_len);
    hdr->ip.ttl = 64;

    hdr->ip.protocol = GetProto(req);

    suri_log(9, "Set IP/Port, direction to %s\n", toserver ? "server" : "client");
    hdr->ip.saddr = toserver ? GetClientIP(req) : GetServerIP(req);
    hdr->ip.daddr = toserver ? GetServerIP(req) : GetClientIP(req);

    if (hdr->ip.protocol == IPPROTO_TCP) {
        hdr->tcp.th_sport = toserver ? GetClientPort(req) : GetServerPort(req);
        hdr->tcp.th_dport = toserver ? GetServerPort(req) : GetClientPort(req);

        hdr->tcp.doff = 5;                  /* 5 dwords = 20 bytes, no options */
        hdr->tcp.syn = flags & TH_SYN ? 1 : 0;
        hdr->tcp.ack = flags & TH_ACK ? 1 : 0;
        hdr->tcp.psh = flags & TH_PUSH ? 1 : 0;
        hdr->tcp.fin = flags & TH_FIN ? 1 : 0;
        suri_log(7, "Set flags syn=%u, ack=%u, psh=%u, fin=%u\n", hdr->tcp.syn, hdr->tcp.ack, hdr->tcp.psh, hdr->tcp.fin);

        // ATTENTION: Suricata does NOT detect unless we set th_win (otherwise, flow will have error events)
        hdr->tcp.th_win = htons(65535);

        GetSeqAck(req, data_len, toserver);

        hdr->tcp.th_seq = toserver ? htonl(ctx->client_seq) : htonl(ctx->server_seq);
        hdr->tcp.th_ack = toserver ? htonl(ctx->client_ack) : htonl(ctx->server_ack);

        // Revert byte order by htonl() for printing
        suri_log(7, "Set %s seq=%u, ack=%u\n", toserver ? "client" : "server", htonl(hdr->tcp.th_seq), htonl(hdr->tcp.th_ack));
    }

    if (data_len > 0) {
        memcpy(pkt + header_len, data, data_len);
    }
    return pkt;
}

// InjectPacket — wrap raw bytes in a minimal Suricata Packet and push
// it through the detection engine.
// We present the payload as a raw segment on a fake loopback device.
static int InjectPacket(ci_request_t *req, const char *data, int data_len, uint16_t flags, int toserver)
{
    if (!g_suri_ready || g_worker_tv == NULL) {
        suri_log(3, "Engine not ready, skipping packet injection\n");
        return -1;
    }

    size_t pkt_len = 0;

    uint8_t *pkt = CreatePacket(req, data, data_len, flags, toserver, &pkt_len);
    if (pkt == NULL) {
        return -1;
    }

    if (GetLiveDevice(req) == NULL) {
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
        TmqhOutputPacketpool(g_worker_tv, p);
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

    // Push packet into the detection pipeline.
    // TmThreadsSlotProcessPkt() is the canonical library-mode injection call
    // (see examples/lib/custom/main.c).
    if (TmThreadsSlotProcessPkt(g_worker_tv, g_worker_tv->tm_slots, p) != TM_ECODE_OK) {
        suri_log(1, "TmThreadsSlotProcessPkt failed\n");
        free(pkt);
        TmqhOutputPacketpool(g_worker_tv, p);
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

    // Suricata owns the packet from here; do not free it ourselves yet
    // We free pkt in ReleasePacket
    // free(pkt);
    return rv;
}

// Called once when the module is loaded
int suri_init_service(ci_service_xdata_t *srv_xdata, struct ci_server_conf *server_conf)
{
    suri_log(5, "Initialise Suricata library\n");

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
        return CI_ERROR;
    }

    // Register a virtual loopback "live" device for packets to be associated with
    if (LiveRegisterDevice("suri_icap0") < 0) {
        suri_log(1, "LiveRegisterDevice failed\n");
        return CI_ERROR;
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
        return CI_ERROR;
    }

    SCEnableDefaultSignalHandlers();

    // Load the config from file
    if (SCLoadYamlConfig() != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    // Initialise the engine, calls SuricataRunModeSetup callback
    SuricataInit();

    SCDetectEngineRegisterRateFilterCallback(RateFilterCallback, NULL);

    if (pthread_create(&g_worker_tid, NULL, SuricataWorkerThread, NULL) != 0) {
        suri_log(1, "pthread_create for worker failed\n");
        return CI_ERROR;
    }

    // Post-init seals threads, starts packet queues, etc.
    SuricataPostInit();

    // Record the exact PID that initialized the engine,
    // so we can conditionally bypass shutdown in child processes.
    g_parent_pid = getpid();

    ci_service_set_preview(srv_xdata, 4096);

    if (MODE == mode_allow204) {
        ci_service_enable_204(srv_xdata);
    }

    // Ask clients to send preview for all content types
    ci_service_set_transfer_preview(srv_xdata, "*");

    suri_log(5, "Suricata engine ready\n");
    g_suri_ready = 1;

    return CI_OK;
}

// Called when c-icap shuts down
void suri_close_service(void)
{
    pid_t current_pid = getpid();
    suri_log(5, "ENTER, g_suri_ready=%d, g_parent_pid=%d, current_pid=%d\n", g_suri_ready, g_parent_pid, current_pid);

    if (!g_suri_ready) {
        return;
    }
    g_suri_ready = 0;

    // ATTENTION: Only tear down threads and force exit if we are running 
    // inside the specific process context that initialized them.
    if (current_pid == g_parent_pid) {
        suri_log(7, "EngineStop()\n");
        EngineStop();

        suri_log(7, "SuricataShutdown()\n");
        SuricataShutdown();

        // SuricataShutdown and the worker's SCTmThreadsSlotPacketLoopFinish
        // must run concurrently (see examples/lib/custom/main.c notes).
        // The pthread_join here ensures the worker has finished before we return.
        suri_log(7, "pthread_join()\n");
        pthread_join(g_worker_tid, NULL);

        suri_log(7, "GlobalsDestroy()\n");
        GlobalsDestroy();

        suri_log(5, "Shutdown complete, current_pid=%d\n", current_pid);
    }
    else {
        suri_log(7, "Bypass Suricata shutdown in child process, current_pid=%d\n", current_pid);
    }
}

void *suri_init_request_data(ci_request_t *req)
{
    suri_log(1, "ENTER\n");

    struct suri_req_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        suri_log(1, "calloc failed for request data\n");
        return NULL;
    }

    if (ci_req_hasbody(req)) {
        ctx->body_buf = dual_ring_buf_create(SRV_SURICATA_INIT_BODY_BUF_SIZE);
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

    struct suri_req_ctx *ctx = (struct suri_req_ctx *)data;
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

int suri_get_response_vars(ci_request_t *req)
{
    struct suri_req_ctx *ctx = ci_service_data(req);

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

void suri_init_tcp_session(struct suri_req_ctx *ctx)
{
    // Open the kernel's secure random device
    // O_CLOEXEC is a good habit to prevent descriptor leaks with fork+exec, even though we don't exec here.
    int fd = open("/dev/urandom", O_RDONLY | __O_CLOEXEC);
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
        goto err; // Failed to read enough bytes
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

int suri_set_seq_numbers(ci_request_t *req)
{
    struct suri_req_ctx *ctx = ci_service_data(req);

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

int suri_handle_inspect_result(ci_request_t *req, int rv)
{
    struct suri_req_ctx *ctx = ci_service_data(req);

    switch (rv) {
    case 1:
        suri_log(5, "InjectPacket returned block\n");
        ci_icap_add_xheader(req, "X-Response-Info: blocked");
        ctx->block = 1;
        break;
    case 0:
        char resp_vars[64];
        if (snprintf(resp_vars, sizeof(resp_vars), "X-Response-Vars: %u,%u", ctx->client_seq, ctx->server_seq) >= 0) {
            suri_log(5, "InjectPacket did not return block, continue processing\n");
            ci_icap_add_xheader(req, "X-Response-Info: continue");
            ci_icap_add_xheader(req, resp_vars);
            break;
        }
        suri_log(1, "snprintf failed\n");
        // fall through to error handling
    case -1:
        suri_log(1, "InjectPacket failed\n");
        ci_icap_add_xheader(req, "X-Response-Info: error");
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

    struct suri_req_ctx *ctx = ci_service_data(req);

    content_len = ci_http_content_length(req);
    suri_log(9, "We expect to read :%" PRINTF_OFF_T " body data\n", (CAST_OFF_T) content_len);

    ci_req_unlock_data(req);

    if (preview_data_len == 0) {
        suri_log(9, "No preview data received, continue processing\n");
        // We send http headers in preview handler, not just body
        // ci_icap_add_xheader(req, "X-Response-Action: continue");
        // return CI_MOD_CONTINUE;
    }

    suri_log(7, "Injecting %d bytes into Suricata\n", preview_data_len);

    // Set to -2 to distinguish uninitialized state
    int rv = -2;

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
    char http_headers[SRV_SURICATA_MAX_HTTP_HDRS];

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
        suri_log(7, "Inject PUSH|ACK payload packet, payload_len=%zu, http_headers_len=%zu, preview_data_len=%d\n",
            payload_len, http_headers_len, preview_data_len);

        ctx->preview_injected = preview_data_len;

        if ((rv = InjectPacket(req, payload, payload_len, TH_PUSH|TH_ACK, req->type == ICAP_REQMOD ? 1 : 0)) != 0) {
            goto out;
        }

        if (!StreamTcpInlineMode() && ACKWINDOW > 0) {
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
    int result = suri_handle_inspect_result(req, rv);

    if (rv == 1) {
        // ATTENTION: We set X-Response-Info for the 204 response, but c-icap does not send any headers with 100 Continue
        // If we return CI_MOD_DONE, c-icap sends 500 Error to the client
        return MODE == mode_allow204 ? CI_MOD_ALLOW204 : CI_MOD_CONTINUE;
    }

    if (result == CI_MOD_ERROR) {
        return CI_MOD_ERROR;
    }

    if (ci_req_hasalldata(req)) {
        suri_log(7, "All data received in preview\n");
    }

    if (preview_data && preview_data_len > 0) {
        dual_ring_buf_write(ctx->body_buf, preview_data, preview_data_len);
    }

    return CI_MOD_CONTINUE;
}

int suri_end_of_data_handler(ci_request_t *req)
{
    struct suri_req_ctx *ctx = ci_service_data(req);

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
    if ((req->type != ICAP_REQMOD || ctx->error) && !ctx->block && !ctx->sent_fin) {
        ctx->sent_fin = 1;

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
    struct suri_req_ctx *ctx = ci_service_data(req);

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

    int rbuf_size = rlen ? *rlen : 0;
    int rbuf_copy_len = 0;

    if (wbuf && wlen && *wlen > 0) {
        int wbuf_size = *wlen;
        int body_buf_copy_len = dual_ring_buf_client_read_available(ctx->body_buf);

        if (body_buf_copy_len > 0) {
            body_buf_copy_len = body_buf_copy_len < wbuf_size ? body_buf_copy_len : wbuf_size;

            suri_log(5, "Send %d bytes from body_buf to client\n", body_buf_copy_len);
            body_buf_copy_len = dual_ring_buf_client_read(ctx->body_buf, wbuf, body_buf_copy_len);

            wbuf_size -= body_buf_copy_len;
        }

        // This sets *wlen to 0 if we have no data to send, so we can set *wlen to CI_EOF below if iseof
        *wlen = body_buf_copy_len;

        if (rbuf && rlen && rbuf_size > 0 && wbuf_size > 0) {
            rbuf_copy_len = (rbuf_size < wbuf_size) ? rbuf_size : wbuf_size;

            suri_log(5, "Send %d bytes from rbuf to client\n", rbuf_copy_len);
            memcpy(wbuf + *wlen, rbuf, rbuf_copy_len);

            *wlen += rbuf_copy_len;
            *rlen = rbuf_copy_len;
            rbuf_size -= rbuf_copy_len;
        }

        int suri_avail = dual_ring_buf_suri_read_available(ctx->body_buf);
        int inject_len = suri_avail + rbuf_copy_len;

        suri_log(5, "Current body_buf_copy_len=%d, rbuf_copy_len=%d, suri avail=%d\n", body_buf_copy_len, rbuf_copy_len, suri_avail);

        if (inject_len > 0) {
            // Advance the suri read pointer, no memcpy
            dual_ring_buf_suri_read(ctx->body_buf, NULL, suri_avail);

            int wbuf_offset = 0;
            if (ctx->preview_injected > 0) {
                inject_len -= ctx->preview_injected;
                wbuf_offset = ctx->preview_injected;
                ctx->preview_injected = 0;  // Reset the counter as we have accounted for the preview buffer in this injection
            }

            if (!StreamTcpInlineMode() && ACKWINDOW > 0) {
                ctx->injected_since_ack += inject_len;
            }

            suri_log(5, "Injecting %d bytes into Suricata, wbuf_offset=%d\n", inject_len, wbuf_offset);
            if ((rv = InjectPacket(req, wbuf + wbuf_offset, inject_len, TH_PUSH|TH_ACK, req->type == ICAP_REQMOD ? 1 : 0)) != 0) {
                *wlen = 0;  // Tell c-icap not to send wbuf to the client
                goto out;
            }
        }

        suri_log(5, "Current wlen=%d, rlen=%d\n", *wlen, rlen ? *rlen : 0);
    }

    if (rbuf && rlen && rbuf_size > 0) {
        suri_log(5, "Buffer new data not sent, rbuf_size=%d\n", rbuf_size);
        int written = dual_ring_buf_write(ctx->body_buf, rbuf + rbuf_copy_len, rbuf_size);
        if (written < rbuf_size) {
            suri_log(1, "Failed to write to body_buf, written=%d < rbuf_size=%d\n", written, rbuf_size);
        }
        *rlen = rbuf_copy_len + written;  // Tell c-icap that we consumed some of the rbuf data
    }

    if (wlen && *wlen == 0 && (ctx->eof == 1 || iseof)) {
        suri_log(5, "Set EOF\n");
        *wlen = CI_EOF;
    }

    if (!StreamTcpInlineMode() && ACKWINDOW > 0) {
        // This io function may be called after end_of_data_handler and when we set CI_EOF above,
        // so do not inject duplicate ACK packets, hence !data->sent_fin and data->injected_since_ack > 0
        if ((ctx->injected_since_ack >= ACKWINDOW || (iseof && ctx->injected_since_ack > 0)) && !ctx->sent_fin) {
            suri_log(7, "Reached ACK window size or iseof, injecting ACK packets, injected_since_ack=%u, ACKWINDOW=%u, iseof=%d, sent_fin=%d\n",
                ctx->injected_since_ack, ACKWINDOW, iseof, ctx->sent_fin);

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
    int result = suri_handle_inspect_result(req, rv);
    if (result == CI_MOD_DONE && (rv == 0 || rv == -2)) {
        return CI_OK;
    }
    return result;
}

int suri_cfg_mode(const char *directive, const char **argv, void *setdata)
{
    if (strcasecmp(argv[0], "disallow204") == 0)
        MODE = mode_disallow204;
    else {
        suri_log(1, "Unknown value '%s' for configuration parameter '%s'\n", argv[0], directive);
        return 0;
    }
    suri_log(2, "Setting parameter: %s\n", directive);
    return 1;
}

int suri_cfg_ackwindow(const char *directive, const char **argv, void *setdata)
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
    ACKWINDOW = size;
    return 1;
}

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
