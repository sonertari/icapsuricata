/*-
 * Suricata IDS ICAP inspection service module
 *
 * Copyright (c) 2026, Soner Tari <sonertari@gmail.com>.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301  USA.
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
 *     flat buffer and injected into Suricata as synthetic TCP payload packets so
 *     the detection engine can evaluate them.
 *   - On a rule match Suricata fires its normal alert path; we additionally hook
 *     the PacketAlert callback to print a c-icap debug line.
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

// For synthetic buffer construction
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

// Maximum body bytes we reassemble per request before handing off to Suricata.
#define SRV_SURICATA_MAX_BODY (256 * 1024)  /* 256 KiB */

static ThreadVars *g_worker_tv  = NULL;
static pthread_t   g_worker_tid = 0;
static int         g_suri_ready = 0;   /* set to 1 after SuricataPostInit */
static pid_t       g_parent_pid = 0;   /* Tracks which process initialized Suricata */

// Per-request data structure
struct suricata_req_data {
    char    *body_buf;   /* flat accumulation buffer                 */
    int      body_len;   /* bytes written so far                     */
    int      body_cap;   /* allocated capacity                       */
    int      sent_len;   /* bytes sent so far                        */
    int      eof;        /* set when end-of-data_handler fires       */
    // int      matched;    /* non-zero if a rule fired on this request */
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
};

enum suri_mode {mode_disallow204, mode_allow204};
static int MODE = mode_allow204;

static int  suri_cfg_mode(const char *directive, const char **argv, void *setdata);
static struct ci_conf_entry suri_conf_variables[] = {
    {"Mode", NULL, suri_cfg_mode, NULL}
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
    "Suricata IDS ICAP inspection",     /* mod_short_descr           */
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
    ci_debug_printf(9, "srv_suricata: SuricataRunModeSetup: ENTER\n");

    // TimeModeSetOffline: we feed synthetic packets with fabricated timestamps,
    // so we do not want the engine to complain about clock skew.
    TimeModeSetOffline();

    g_worker_tv = SCRunModeLibCreateThreadVars(1 /* worker_id */);
    if (g_worker_tv == NULL) {
        ci_debug_printf(1, "srv_suricata: SuricataRunModeSetup: SCRunModeLibCreateThreadVars failed\n");
        return -1;
    }
    return 0;
}

// Packet injection helper
static void ReleasePacket(Packet *p)
{
    ci_debug_printf(9, "srv_suricata: ReleasePacket: ENTER\n");
    if (PacketCheckAction(p, ACTION_DROP)) {
        ci_debug_printf(5, "srv_suricata: ReleasePacket: Dropping packet!\n");
    }

    if (p->ext_pkt != NULL) {
        ci_debug_printf(9, "srv_suricata: ReleasePacket: Freeing packet buffer\n");
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

    ci_debug_printf(9, "srv_suricata: SuricataWorkerThread: ENTER\n");

    if (SCRunModeLibSpawnWorker(g_worker_tv) != 0) {
        ci_debug_printf(1, "srv_suricata: SuricataWorkerThread: SCRunModeLibSpawnWorker failed\n");
        pthread_exit((void *)(intptr_t)EXIT_FAILURE);
    }

    ci_debug_printf(5, "srv_suricata: SuricataWorkerThread: SuricataMainLoop()\n");
    SuricataMainLoop();

    // Note that there is some thread synchronization between this
    // function and SuricataShutdown such that they must be run
    // concurrently at this time before either will exit.
    if (g_worker_tv != NULL) {
        ci_debug_printf(5, "srv_suricata: SuricataWorkerThread: SCTmThreadsSlotPacketLoopFinish()\n");
        SCTmThreadsSlotPacketLoopFinish(g_worker_tv);
    }

    ci_debug_printf(5, "srv_suricata: SuricataWorkerThread: EXIT\n");
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
    struct suricata_req_data *data = ci_service_data(req);
    ci_debug_printf(9, "srv_suricata: GetClientIP: X-Client-IP=%s\n", ci_icap_request_get_header(req, "X-Client-IP"));

    if (!data->client_ip_set) {
        data->client_ip = htonl(0x7F000001);  /* Fallback to 127.0.0.1 */
        data->client_ip_set = 1;

        const char *ip_str = ci_icap_request_get_header(req, "X-Client-IP");
        if (ip_str) {
            inet_pton(AF_INET, ip_str, &data->client_ip);
        }
    }

    return data->client_ip;
}

static uint32_t GetClientPort(ci_request_t *req)
{
    struct suricata_req_data *data = ci_service_data(req);
    ci_debug_printf(9, "srv_suricata: GetClientPort: X-Client-Port=%s\n", ci_icap_request_get_header(req, "X-Client-Port"));

    if (!data->client_port_set) {
        data->client_port = htons(12345);  /* Fallback to 12345 */
        data->client_port_set = 1;

        const char *port_str = ci_icap_request_get_header(req, "X-Client-Port");
        if (port_str) {
            data->client_port = htons(atoi(port_str));
        }
    }

    return data->client_port;
}

static uint32_t GetServerIP(ci_request_t *req)
{
    struct suricata_req_data *data = ci_service_data(req);
    ci_debug_printf(9, "srv_suricata: GetServerIP: X-Server-IP=%s\n", ci_icap_request_get_header(req, "X-Server-IP"));

    if (!data->server_ip_set) {
        data->server_ip = htonl(0x7F000001);  /* Fallback to 127.0.0.1 */
        data->server_ip_set = 1;

        const char *ip_str = ci_icap_request_get_header(req, "X-Server-IP");
        if (ip_str) {
            inet_pton(AF_INET, ip_str, &data->server_ip);
        }
    }

    return data->server_ip;
}

static uint32_t GetServerPort(ci_request_t *req)
{
    struct suricata_req_data *data = ci_service_data(req);
    ci_debug_printf(9, "srv_suricata: GetServerPort: X-Server-Port=%s\n", ci_icap_request_get_header(req, "X-Server-Port"));

    if (!data->server_port_set) {
        data->server_port = htons(80);  /* Fallback to 80 */
        data->server_port_set = 1;

        const char *port_str = ci_icap_request_get_header(req, "X-Server-Port");
        if (port_str) {
            data->server_port = htons(atoi(port_str));
        }
    }

    return data->server_port;
}

static uint8_t GetProto(ci_request_t *req)
{
    struct suricata_req_data *data = ci_service_data(req);
    ci_debug_printf(9, "srv_suricata: GetProto: X-Proto=%s\n", ci_icap_request_get_header(req, "X-Proto"));

    if (!data->proto_set) {
        data->proto = IPPROTO_TCP;     /* Default to TCP */
        data->proto_set = 1;

        const char *proto_str = ci_icap_request_get_header(req, "X-Proto");
        if (proto_str && strcasecmp(proto_str, "UDP") == 0) {
            data->proto = IPPROTO_UDP;
        }
    }

    return data->proto;
}

static LiveDevice *GetLiveDevice(ci_request_t *req)
{
    struct suricata_req_data *data = ci_service_data(req);

    if (!data->dev_set) {
        data->dev_set = 1;

        data->dev = LiveGetDevice("suri_icap0");
        if (data->dev == NULL) {
            ci_debug_printf(1, "srv_suricata: BuildAndInjectPacket: LiveGetDevice failed\n");
        }
        else {
            ci_debug_printf(5, "srv_suricata: BuildAndInjectPacket: obtained LiveDevice for injection\n");
        }
    }

    return data->dev;
}

// BuildAndInjectPacket — wrap raw bytes in a minimal Suricata Packet and push
// it through the detection engine.
// We present the payload as a raw TCP segment on a fake loopback device.
// Suricata's DETECT module will match content-based signatures against the
// raw bytes regardless of the encapsulation we claim.
static int BuildAndInjectPacket(const char *data, int len, ci_request_t *req)
{
    if (!g_suri_ready || g_worker_tv == NULL) {
        ci_debug_printf(3, "srv_suricata: BuildAndInjectPacket: engine not ready, skipping packet injection\n");
        return -1;
    }

    if (GetLiveDevice(req) == NULL) {
        return -1;
    }

    // Construct the combined buffer containing the synthetic IP/TCP headers 
    // followed immediately by the payload data chunks.
    size_t header_len = sizeof(struct fake_pkt_hdr);
    size_t total_len = header_len + len;
    uint8_t *pkt_buf = malloc(total_len);
    if (pkt_buf == NULL) {
        ci_debug_printf(1, "srv_suricata: BuildAndInjectPacket: allocation for pkt_buf failed\n");
        return -1;
    }

    // Populate IP Header from icap extended headers for network context
    struct fake_pkt_hdr *hdr = (struct fake_pkt_hdr *)pkt_buf;
    memset(hdr, 0, header_len);

    hdr->ip.version = 4;
    hdr->ip.ihl = 5;                        /* 5 dwords = 20 bytes */
    hdr->ip.tot_len = htons(total_len);
    hdr->ip.ttl = 64;

    hdr->ip.protocol = GetProto(req);

    hdr->ip.saddr = GetClientIP(req);
    hdr->ip.daddr = GetServerIP(req);

    // Populate TCP/UDP Header Ports from extended headers for network context
    // Note: The memory layout of tcphdr and udphdr both place the 16-bit 
    // source port at byte offset 0, and dest port at byte offset 2. 
    // Writing to hdr->tcp works perfectly for layer-4 bucketing.
    hdr->tcp.source = GetClientPort(req);
    hdr->tcp.dest = GetServerPort(req);

    // If it is TCP, set the data offset and flags
    if (hdr->ip.protocol == IPPROTO_TCP) {
        hdr->tcp.doff = 5;                  /* 5 dwords = 20 bytes, no options */
        hdr->tcp.ack = 1;                   /* Pretend an established segment */
    }

    // Append the raw ICAP body payload bytes right after the headers
    memcpy(pkt_buf + header_len, data, len);

    Packet *p = PacketGetFromQueueOrAlloc();
    if (unlikely(p == NULL)) {
        ci_debug_printf(1, "srv_suricata: BuildAndInjectPacket: PacketGetFromQueueOrAlloc failed\n");
        free(pkt_buf);
        return -1;
    }

    // Hand over the synthesized buffer to the Suricata Packet allocation
    if (PacketSetData(p, pkt_buf, total_len) == -1) {
        ci_debug_printf(1, "srv_suricata: BuildAndInjectPacket: PacketSetData failed\n");
        free(pkt_buf);
        TmqhOutputPacketpool(g_worker_tv, p);
        return -1;
    }

    // Timestamp — engine is in offline mode, so any value is fine.
    struct timeval tv;
    gettimeofday(&tv, NULL);
    SCTime_t ts = SCTIME_FROM_TIMEVAL(&tv);

    SCPacketSetSource(p, PKT_SRC_WIRE);
    SCPacketSetTime(p, ts);

    // LINKTYPE_RAW (DLT_RAW): raw IP, no Ethernet header.
    // Because we are feeding LINKTYPE_RAW, Suricata expects the packet 
    // buffer data to immediately start with a valid IP header.
    SCPacketSetDatalink(p, LINKTYPE_RAW);

    SCPacketSetLiveDevice(p, GetLiveDevice(req));
    SCPacketSetReleasePacket(p, ReleasePacket);

    // Push packet into the detection pipeline.
    // TmThreadsSlotProcessPkt() is the canonical library-mode injection call
    // (see examples/lib/custom/main.c).
    if (TmThreadsSlotProcessPkt(g_worker_tv, g_worker_tv->tm_slots, p) != TM_ECODE_OK) {
        ci_debug_printf(1, "srv_suricata: BuildAndInjectPacket: TmThreadsSlotProcessPkt failed\n");
        free(pkt_buf);
        TmqhOutputPacketpool(g_worker_tv, p);
        return -1;
    }

    int rv = 0;

    // QUERY VERDICT
    if (p->action & ACTION_DROP) {
        ci_debug_printf(1, "srv_suricata: BuildAndInjectPacket: Action verdict MATCHED a blocking signature, drop reason: %s\n",
            PacketDropReasonToString(p->drop_reason));
        rv = 1;
    }

    LiveDevicePktsIncr(GetLiveDevice(req));

    // Suricata owns the packet from here; do not free it ourselves yet
    // We free pkt_buf in ReleasePacket
    // free(pkt_buf);
    return rv;
}

// Called once when the module is loaded
int suri_init_service(ci_service_xdata_t *srv_xdata,
                      struct ci_server_conf *server_conf)
{
    ci_debug_printf(5, "srv_suricata: suri_init_service: initialising Suricata library...\n");

    // SuricataPreInit must be the very first call.  We pass the service name
    // as argv[0] equivalent so Suricata can locate its own binary path.
    SuricataPreInit("srv_suricata");

    // Offline/library mode, no live capture device required
    SCRunmodeSet(RUNMODE_LIB);

    // Finalize runmode selection, required before SuricataInit
    if (SCFinalizeRunMode() != TM_ECODE_OK) {
        ci_debug_printf(1, "srv_suricata: suri_init_service: SCFinalizeRunMode failed\n");
        return CI_ERROR;
    }

    // Register a virtual loopback "live" device for packets to be associated with
    if (LiveRegisterDevice("suri_icap0") < 0) {
        ci_debug_printf(1, "srv_suricata: suri_init_service: LiveRegisterDevice failed\n");
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
        ci_debug_printf(1, "srv_suricata: suri_init_service: SCConfSet runmode failed\n");
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
        ci_debug_printf(1, "srv_suricata: suri_init_service: pthread_create for worker failed\n");
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

    ci_debug_printf(5, "srv_suricata: suri_init_service: Suricata engine ready\n");
    g_suri_ready = 1;

    return CI_OK;
}

// Called when c-icap shuts down
void suri_close_service(void)
{
    pid_t current_pid = getpid();
    ci_debug_printf(5, "srv_suricata: suri_close_service: ENTER, g_suri_ready=%d, g_parent_pid=%d, current_pid=%d\n", g_suri_ready, g_parent_pid, current_pid);

    if (!g_suri_ready) {
        return;
    }
    g_suri_ready = 0;

    // ATTENTION: Only tear down threads and force exit if we are running 
    // inside the specific process context that initialized them.
    if (current_pid == g_parent_pid) {
        ci_debug_printf(7, "srv_suricata: suri_close_service: EngineStop()\n");
        EngineStop();

        ci_debug_printf(7, "srv_suricata: suri_close_service: SuricataShutdown()\n");
        SuricataShutdown();

        // SuricataShutdown and the worker's SCTmThreadsSlotPacketLoopFinish
        // must run concurrently (see examples/lib/custom/main.c notes).
        // The pthread_join here ensures the worker has finished before we return.
        ci_debug_printf(7, "srv_suricata: suri_close_service: pthread_join()\n");
        pthread_join(g_worker_tid, NULL);

        ci_debug_printf(7, "srv_suricata: suri_close_service: GlobalsDestroy()\n");
        GlobalsDestroy();

        ci_debug_printf(5, "srv_suricata: suri_close_service: shutdown complete, current_pid=%d\n", current_pid);
    }
    else {
        ci_debug_printf(7, "srv_suricata: suri_close_service: Bypass Suricata shutdown in child process, current_pid=%d\n", current_pid);
    }
}

void *suri_init_request_data(ci_request_t *req)
{
    ci_debug_printf(1, "srv_suricata: suri_init_request_data: ENTER\n");

    struct suricata_req_data *d = calloc(1, sizeof(*d));
    if (!d) {
        ci_debug_printf(1, "srv_suricata: suri_init_request_data: calloc for request data failed\n");
        return NULL;
    }

    if (ci_req_hasbody(req)) {
        d->body_cap = 64 * 1024;  /* start with 64 KiB, grown in suri_io */
        d->body_buf = malloc(d->body_cap);
        if (!d->body_buf) {
            ci_debug_printf(1, "srv_suricata: suri_init_request_data: malloc for body buf failed\n");
            free(d);
            return NULL;
        }
    }

    return d;
}

void suri_release_request_data(void *data)
{
    ci_debug_printf(5, "srv_suricata: suri_release_request_data: ENTER\n");

    struct suricata_req_data *d = (struct suricata_req_data *)data;
    if (!d)
        return;
    ci_debug_printf(5, "srv_suricata: suri_release_request_data: body_len=%d\n", d->body_len);
    free(d->body_buf);
    free(d);
}

static int AppendToBodyBuf(struct suricata_req_data *d,
                           const char *buf, int len)
{
    if (!buf || len <= 0)
        return 0;

    // Enforce the hard cap
    if (d->body_len >= SRV_SURICATA_MAX_BODY) {
        ci_debug_printf(4, "srv_suricata: body cap reached, dropping chunk\n");
        return 0;
    }
    if (d->body_len + len > SRV_SURICATA_MAX_BODY)
        len = SRV_SURICATA_MAX_BODY - d->body_len;

    // Grow buffer if needed
    if (d->body_len + len > d->body_cap) {
        int new_cap = d->body_cap * 2;
        while (new_cap < d->body_len + len)
            new_cap *= 2;
        if (new_cap > SRV_SURICATA_MAX_BODY)
            new_cap = SRV_SURICATA_MAX_BODY;

        char *tmp = realloc(d->body_buf, new_cap);
        if (!tmp) {
            ci_debug_printf(1, "srv_suricata: realloc failed\n");
            return -1;
        }
        d->body_buf = tmp;
        d->body_cap = new_cap;
    }

    memcpy(d->body_buf + d->body_len, buf, len);
    d->body_len += len;
    return len;
}

int suri_check_preview_handler(char *preview_data, int preview_data_len, ci_request_t *req)
{
    ci_off_t content_len;

    struct suricata_req_data *data = ci_service_data(req);

    content_len = ci_http_content_length(req);
    ci_debug_printf(9, "We expect to read :%" PRINTF_OFF_T " body data\n", (CAST_OFF_T) content_len);

    ci_req_unlock_data(req);

    if (preview_data_len == 0) {
        ci_debug_printf(5, "srv_suricata: suri_check_preview_handler: No preview data received, continue processing\n");
        ci_icap_add_xheader(req, "X-Response-Action: continue");
        return CI_MOD_CONTINUE;
    }

    ci_debug_printf(7, "srv_suricata: suri_check_preview_handler: Injecting %d bytes into Suricata\n", preview_data_len);
    int rv = BuildAndInjectPacket(preview_data, preview_data_len, req);

    if (rv == 1) {
        ci_debug_printf(5, "srv_suricata: suri_check_preview_handler: BuildAndInjectPacket returned block\n");
        ci_icap_add_xheader(req, "X-Response-Info: blocked");
        data->eof = 1;
        // If we return CI_MOD_DONE, c-icap sends 500 Error to the client
        // return CI_MOD_DONE;
        return MODE == mode_allow204 ? CI_MOD_ALLOW204 : CI_MOD_CONTINUE;
    }
    else if (rv == -1) {
        ci_debug_printf(1, "srv_suricata: suri_check_preview_handler: BuildAndInjectPacket failed\n");
        ci_icap_add_xheader(req, "X-Response-Info: error");
        data->eof = 1;
        return CI_MOD_ERROR;
    }

    ci_debug_printf(5, "srv_suricata: suri_check_preview_handler: BuildAndInjectPacket did not return block, continue processing\n");

    if (MODE == mode_allow204) {
        ci_debug_printf(7, "srv_suricata: suri_check_preview_handler: Allow204 mode enabled\n");
        ci_icap_add_xheader(req, "X-Response-Action: continue");
        data->eof = 1;
        return CI_MOD_ALLOW204;
    }

    // mode_disallow204
    if (ci_req_hasalldata(req)) {
        ci_debug_printf(7, "srv_suricata: suri_check_preview_handler: All data received in preview\n");
        data->eof = 1;
    }

    ci_debug_printf(8, "srv_suricata: suri_check_preview_handler: Process rest of request\n");

    // TODO: Use ring buffers as in c-icap examples
    // ci_ring_buf_write(data->body, preview_data, preview_data_len);
    AppendToBodyBuf(data, preview_data, preview_data_len);
    ci_icap_add_xheader(req, "X-Response-Action: continue");

    return CI_MOD_CONTINUE;
}

int suri_end_of_data_handler(ci_request_t *req)
{
    struct suricata_req_data *data = ci_service_data(req);

    ci_debug_printf(5, "srv_suricata: suri_end_of_data: ENTER, body_len=%d bytes\n", data->body_len);

    // Only inject if we haven't already done so in the preview handler
    if (!data->eof && data->body_len > 0) {
        ci_debug_printf(5, "srv_suricata: suri_end_of_data: Injecting %d bytes into Suricata\n", data->body_len);
        int rv = BuildAndInjectPacket(data->body_buf, data->body_len, req);
        if (rv == 1) {
            ci_debug_printf(5, "srv_suricata: suri_end_of_data: BuildAndInjectPacket returned block\n");
            ci_icap_add_xheader(req, "X-Response-Info: blocked");
            return CI_MOD_DONE;
        }
        else if (rv == -1) {
            ci_debug_printf(1, "srv_suricata: suri_end_of_data: BuildAndInjectPacket failed\n");
            ci_icap_add_xheader(req, "X-Response-Info: error");
            return CI_MOD_ERROR;
        }

        ci_debug_printf(5, "srv_suricata: suri_end_of_data: BuildAndInjectPacket did not return block, continue processing\n");
        ci_icap_add_xheader(req, "X-Response-Info: continue");
    }

    data->eof = 1;
    return CI_MOD_DONE;
}

int suri_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof, ci_request_t *req)
{
    struct suricata_req_data *d = ci_service_data(req);
    int ret = CI_OK;

    ci_debug_printf(5, "srv_suricata: suri_io: ENTER rbuf=%p, wbuf=%p, rlen=%p, wlen=%p, *rlen=%d, *wlen=%d, iseof=%d, req=%p\n",
        rbuf ? rbuf : NULL, wbuf ? wbuf : NULL, rlen ? rlen : NULL, wlen ? wlen : NULL, rlen ? *rlen : 0, wlen ? *wlen : 0, iseof, req);

    // Simply record the new data
    if (rbuf && rlen && *rlen > 0) {
        ci_debug_printf(5, "srv_suricata: suri_io: AppendToBodyBuf %d bytes\n", *rlen);
        AppendToBodyBuf(d, rbuf, *rlen);
    }

    if (wlen && *wlen == 0 && (d->eof == 1 || iseof)) {
        ci_debug_printf(5, "srv_suricata: suri_io: Set EOF\n");
        *wlen = CI_EOF;
    }

    return ret;
}

int suri_cfg_mode(const char *directive, const char **argv, void *setdata)
{
    if (strcasecmp(argv[0], "disallow204") == 0)
        MODE = mode_disallow204;
    else {
        ci_debug_printf(1, "Unknown value '%s' for configuration parameter '%s'\n", argv[0], directive);
        return 0;
    }
    return 1;
}
