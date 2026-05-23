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
 * srv_suricata.c — Minimalist c-icap service module using libsuricata
 *
 * PROOF-OF-CONCEPT — Not production ready.
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
 *   - No blocking/dropping is performed in this PoC — detect-only.
 *
 * Build:
 *   See Makefile in the same directory.
 *
 * References:
 *   • c-icap echo service  — services/echo/srv_echo.c
 *   • libsuricata custom   — examples/lib/custom/main.c
 *   • Suricata lib API     — src/suricata.h, src/lib.h, src/detect.h
 */

/* ── system ──────────────────────────────────────────────────────────────── */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

/* ── c-icap ──────────────────────────────────────────────────────────────── */
#include "c-icap.h"  /* CI_DECLARE_FUNC, ci_request_t, … */
#include "service.h"
#include "header.h"
#include "body.h"
#include "simple_api.h"
#include "debug.h"
#include "cfg_param.h"

/* ── libsuricata ─────────────────────────────────────────────────────────── */
/*
 * These headers live under  $(suricata-src)/src/  and are installed via
 * `make install-headers`.  Adjust the include path in the Makefile if
 * your installation places them differently.
 */
#include <suricata/suricata.h>       /* SuricataPreInit / SuricataInit / … */
#include <suricata/detect.h>         /* SCDetectEngineRegisterRateFilterCallback */
#include <suricata/conf.h>           /* SCConfSet / SCConfGet                  */
#include <suricata/runmodes.h>       /* SCRunmodeSet, RUNMODE_LIB, …       */
#include <suricata/tm-threads.h>     /* TM_ECODE_OK, SCFinalizeRunMode     */
#include <suricata/util-debug.h>     /* SCLogNotice / ci_debug_printf      */
#include <suricata/packet.h>         /* Packet, PacketGetFromQueueOrAlloc  */
#include <suricata/decode.h>         /* PKT_SRC_WIRE, PacketSetData        */
#include <suricata/util-time.h>      /* SCTIME_FROM_TIMEVAL                */
#include <suricata/runmode-lib.h>
#include <suricata/action-globals.h>

// For synthetic buffer construction
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Module-wide globals
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Maximum body bytes we reassemble per request before handing off to Suricata.
 * Keep small for the PoC; bump later or switch to streaming chunks.
 */
#define SRV_SURICATA_MAX_BODY (256 * 1024)  /* 256 KiB */

/*
 * Suricata worker thread bookkeeping (library-mode pattern from custom/main.c).
 */
static ThreadVars *g_worker_tv  = NULL;
static pthread_t   g_worker_tid = 0;
static int         g_suri_ready = 0;   /* set to 1 after SuricataPostInit */
static pid_t       g_parent_pid = 0;   /* Tracks which process initialized Suricata */

/* ── Suricata library worker thread ──────────────────────────────────────── */

/*
 * The library runmode needs at least one ThreadVars created in a runmode-setup
 * callback before SuricataInit seals the threads.
 */
static int SuricataRunModeSetup(void)
{
    ci_debug_printf(1, "srv_suricata: SuricataRunModeSetup: ENTER\n");

    /*
     * TimeModeSetOffline: we feed synthetic packets with fabricated timestamps,
     * so we do not want the engine to complain about clock skew.
     */
    TimeModeSetOffline();

    g_worker_tv = SCRunModeLibCreateThreadVars(1 /* worker_id */);
    if (g_worker_tv == NULL) {
        ci_debug_printf(1, "srv_suricata: SuricataRunModeSetup: SCRunModeLibCreateThreadVars failed\n");
        return -1;
    }
    return 0;
}

/*
 * Worker thread body: keeps the Suricata slot loop alive so that packets we
 * inject via TmThreadsSlotProcessPkt() are actually processed.
 *
 * In a real module this thread would run for the process lifetime.  Here we
 * simply block inside SCRunModeLibSpawnWorker which returns only when the
 * engine is stopped.
 */
static void *SuricataWorkerThread(void *arg)
{
    (void)arg;

    ci_debug_printf(1, "srv_suricata: SuricataWorkerThread: ENTER\n");

    if (SCRunModeLibSpawnWorker(g_worker_tv) != 0) {
        ci_debug_printf(1, "srv_suricata: SuricataWorkerThread: SCRunModeLibSpawnWorker failed\n");
        pthread_exit((void *)(intptr_t)EXIT_FAILURE);
    }

    ci_debug_printf(5, "srv_suricata: SuricataWorkerThread: SuricataMainLoop()\n");
    SuricataMainLoop();

    /* Cleanup.
     *
     * Note that there is some thread synchronization between this
     * function and SuricataShutdown such that they must be run
     * concurrently at this time before either will exit. */
    if (g_worker_tv != NULL) {
        ci_debug_printf(5, "srv_suricata: SuricataWorkerThread: SCTmThreadsSlotPacketLoopFinish()\n");
        SCTmThreadsSlotPacketLoopFinish(g_worker_tv);
    }

    ci_debug_printf(1, "srv_suricata: SuricataWorkerThread: EXIT\n");
    pthread_exit((void *)(intptr_t)EXIT_SUCCESS);
}

/* ── Packet injection helper ─────────────────────────────────────────────── */
static void ReleasePacket(Packet *p)
{
    ci_debug_printf(1, "srv_suricata: ReleasePacket: ENTER\n");
    if (PacketCheckAction(p, ACTION_DROP)) {
        ci_debug_printf(1, "srv_suricata: ReleasePacket: Dropping packet!\n");
        SCLogNotice("Dropping packet!");
    }

    /* As we overode the default release function, we must release or
     * free the packet. */
    PacketFreeOrRelease(p);
}

/*
 * Minimal 40-byte raw Layer 3 / Layer 4 structure 
 * packed to ensure precise network formatting alignment.
 */
struct __attribute__((__packed__)) fake_pkt_hdr {
    struct iphdr ip;
    struct tcphdr tcp;
};

/*
 * BuildAndInjectPacket — wrap raw bytes in a minimal Suricata Packet and push
 * it through the detection engine.
 *
 * We present the payload as a raw TCP segment on a fake loopback device.
 * Suricata's DETECT module will match content-based signatures against the
 * raw bytes regardless of the encapsulation we claim.
 *
 * @param data    Pointer to the body buffer.
 * @param len     Number of bytes to inspect.
 */
static void BuildAndInjectPacket(const uint8_t *data, int len)
{
    if (!g_suri_ready || g_worker_tv == NULL) {
        ci_debug_printf(3, "srv_suricata: BuildAndInjectPacket: engine not ready, skipping packet injection\n");
        return;
    }

    Packet *p = PacketGetFromQueueOrAlloc();
    if (unlikely(p == NULL)) {
        ci_debug_printf(1, "srv_suricata: BuildAndInjectPacket: PacketGetFromQueueOrAlloc failed\n");
        return;
    }

    /* Timestamp — engine is in offline mode, so any value is fine. */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    SCTime_t ts = SCTIME_FROM_TIMEVAL(&tv);

    SCPacketSetSource(p, PKT_SRC_WIRE);
    SCPacketSetTime(p, ts);

    /*
     * LINKTYPE_RAW (DLT_RAW): raw IP, no Ethernet header.
     * Because we are feeding LINKTYPE_RAW, Suricata expects the packet 
     * buffer data to immediately start with a valid IP header.
     */
    SCPacketSetDatalink(p, LINKTYPE_RAW);

    LiveDevice *dev = LiveGetDevice("suri_icap0");
    if (dev != NULL) {
        ci_debug_printf(5, "srv_suricata: BuildAndInjectPacket: obtained LiveDevice for injection\n");
    } else {
        ci_debug_printf(1, "srv_suricata: BuildAndInjectPacket: LiveGetDevice failed\n");
        TmqhOutputPacketpool(g_worker_tv, p);
        return;
    }

    SCPacketSetLiveDevice(p, dev);
    SCPacketSetReleasePacket(p, ReleasePacket);

    /* * Construct the combined buffer containing the synthetic IP/TCP headers 
     * followed immediately by the payload data chunks.
     */
    size_t header_len = sizeof(struct fake_pkt_hdr);
    size_t total_len = header_len + len;
    uint8_t *pkt_buf = malloc(total_len);
    if (pkt_buf == NULL) {
        ci_debug_printf(1, "srv_suricata: BuildAndInjectPacket: allocation for pkt_buf failed\n");
        TmqhOutputPacketpool(g_worker_tv, p);
        return;
    }

    struct fake_pkt_hdr *hdr = (struct fake_pkt_hdr *)pkt_buf;
    memset(hdr, 0, header_len);

    /* --- Populate Minimal IPv4 Header --- */
    hdr->ip.version = 4;
    hdr->ip.ihl = 5;                        /* 5 dwords = 20 bytes */
    hdr->ip.tot_len = htons(total_len);
    hdr->ip.ttl = 64;
    hdr->ip.protocol = IPPROTO_TCP;         /* Identifies payload as TCP */
    hdr->ip.saddr = htonl(0x7F000001);      /* Source: 127.0.0.1 */
    hdr->ip.daddr = htonl(0x7F000001);      /* Destination: 127.0.0.1 */

    /* --- Populate Minimal TCP Header --- */
    hdr->tcp.source = htons(12345);         /* Fake ephemeral source port */
    hdr->tcp.dest = htons(80);              /* Fake destination port (HTTP) */
    hdr->tcp.doff = 5;                      /* 5 dwords = 20 bytes, no options */
    hdr->tcp.ack = 1;                       /* Pretend this is an established data segment */

    /* Append the raw ICAP body payload bytes right after the headers */
    memcpy(pkt_buf + header_len, data, len);

    /* Hand over the synthesized buffer to the Suricata Packet allocation */
    if (PacketSetData(p, pkt_buf, total_len) == -1) {
        ci_debug_printf(1, "srv_suricata: BuildAndInjectPacket: PacketSetData failed\n");
        free(pkt_buf);
        TmqhOutputPacketpool(g_worker_tv, p);
        return;
    }

    /* * Suricata copies the contents internally when PacketSetData is called, 
     * meaning we must clean up our temporary layout allocation right here.
     */
    free(pkt_buf);

    /*
     * Push packet into the detection pipeline.
     * TmThreadsSlotProcessPkt() is the canonical library-mode injection call
     * (see examples/lib/custom/main.c line 118).
     */
    if (TmThreadsSlotProcessPkt(g_worker_tv, g_worker_tv->tm_slots, p) != TM_ECODE_OK) {
        ci_debug_printf(1, "srv_suricata: BuildAndInjectPacket: TmThreadsSlotProcessPkt failed\n");
        TmqhOutputPacketpool(g_worker_tv, p);
    }

    /* --- QUERY VERDICT HERE (Immediately after processing completes) --- */
    if (p->action & ACTION_DROP) {
        ci_debug_printf(1, "srv_suricata: BuildAndInjectPacket: Action verdict MATCHED a blocking signature, drop reason: %s\n",
            PacketDropReasonToString(p->drop_reason));
    }

    LiveDevicePktsIncr(dev);
    /* Suricata owns the packet from here; do not free it ourselves. */
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Per-request data structure
 * ═══════════════════════════════════════════════════════════════════════════ */

struct suricata_req_data {
    uint8_t *body_buf;   /* flat accumulation buffer                    */
    int      body_len;   /* bytes written so far                        */
    int      body_cap;   /* allocated capacity                          */
    int      sent_len;   /* bytes sent so far                        */
    int      eof;        /* set when end-of-data_handler fires          */
    int      matched;    /* non-zero if a rule fired on this request    */
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Forward declarations — c-icap handler prototypes
 * ═══════════════════════════════════════════════════════════════════════════ */

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

/* ═══════════════════════════════════════════════════════════════════════════
 * ci_service_module_t registration
 * ═══════════════════════════════════════════════════════════════════════════ */

static ci_service_module_t suricata_service = {
    "suricata",                         /* mod_name              */
    "Suricata IDS ICAP inspection PoC", /* mod_short_descr       */
    ICAP_RESPMOD | ICAP_REQMOD,         /* mod_type              */
    suri_init_service,                  /* mod_init_service      */
    NULL,                               /* post_init_service     */
    suri_close_service,                 /* mod_close_service     */
    suri_init_request_data,             /* mod_init_request_data */
    suri_release_request_data,          /* mod_release_request_data */
    suri_check_preview_handler,         /* mod_check_preview_handler */
    suri_end_of_data_handler,           /* mod_end_of_data_handler   */
    suri_io,                            /* mod_service_io            */
    suri_conf_variables,                /* conf_variables            */
    NULL                                /* xdata                     */
};

/* Macro that registers the service with c-icap's module loader. */
_CI_DECLARE_SERVICE(suricata_service);

static uint8_t RateFilterCallback(const Packet *p, const uint32_t sid, const uint32_t gid,
        const uint32_t rev, uint8_t original_action, uint8_t new_action, void *arg)
{
    /* Don't change the action. */
    return new_action;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * suri_init_service — called once when the module is loaded
 * ═══════════════════════════════════════════════════════════════════════════ */

int suri_init_service(ci_service_xdata_t *srv_xdata,
                      struct ci_server_conf *server_conf)
{
    ci_debug_printf(5, "srv_suricata: suri_init_service: initialising Suricata library...\n");

    /* ── 1. Bootstrap Suricata ─────────────────────────────────────────── */

    /*
     * SuricataPreInit must be the very first call.  We pass the service name
     * as argv[0] equivalent so Suricata can locate its own binary path.
     */
    SuricataPreInit("srv_suricata");

    /* Offline / library mode — no live capture device required. */
    SCRunmodeSet(RUNMODE_LIB);

    /* Finalize runmode selection — required before SuricataInit. */
    if (SCFinalizeRunMode() != TM_ECODE_OK) {
        ci_debug_printf(1, "srv_suricata: suri_init_service: SCFinalizeRunMode failed\n");
        return CI_ERROR;
    }

    /* ── 3. Register a loopback "live" device ───────────────────────────── */

    /*
     * Even in library mode the engine needs a LiveDevice for packets to be
     * associated with.  We create a virtual one.
     */
    if (LiveRegisterDevice("suri_icap0") < 0) {
        ci_debug_printf(1, "srv_suricata: suri_init_service: LiveRegisterDevice failed\n");
        return CI_ERROR;
    }
    /* ── 4. Register our custom runmode with its setup callback ─────────── */

    RunModeRegisterNewRunMode(
        RUNMODE_LIB,
        "icap",
        "c-icap ICAP inspection runmode",
        SuricataRunModeSetup,
        NULL /* no teardown callback needed for PoC */
    );

    /* Tell Suricata to use our custom runmode. */
    if (!SCConfSet("runmode", "icap")) {
        ci_debug_printf(1, "srv_suricata: suri_init_service: SCConfSet runmode failed\n");
        return CI_ERROR;
    }

    SCEnableDefaultSignalHandlers();

    /* ── 5. Load the config file ──────────────────────────── */

    if (SCLoadYamlConfig() != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    /* ── 6. Initialise the engine (calls SuricataRunModeSetup callback) ─── */

    SuricataInit();

    SCDetectEngineRegisterRateFilterCallback(RateFilterCallback, NULL);

    /* ── 7. Spawn the worker thread ─────────────────────────────────────── */

    if (pthread_create(&g_worker_tid, NULL, SuricataWorkerThread, NULL) != 0) {
        ci_debug_printf(1, "srv_suricata: suri_init_service: pthread_create for worker failed\n");
        return CI_ERROR;
    }

    /* ── 8. Post-init (seals threads, starts packet queues, etc.) ────────── */

    SuricataPostInit();
    g_parent_pid = getpid(); /* Record the exact PID that initialized the engine */
    g_suri_ready = 1;

    ci_debug_printf(5, "srv_suricata: suri_init_service: Suricata engine ready\n");

    /* ── 9. Advertise ICAP capabilities ─────────────────────────────────── */

    /* Request up to 4 KiB of preview data. */
    ci_service_set_preview(srv_xdata, 4096);

    /* We support 204 (no modification) responses. */
    ci_service_enable_204(srv_xdata);

    /* Ask clients to send preview for all content types. */
    ci_service_set_transfer_preview(srv_xdata, "*");

    return CI_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * suri_close_service — called when c-icap shuts down
 * ═══════════════════════════════════════════════════════════════════════════ */

void suri_close_service(void)
{
    pid_t current_pid = getpid();
    ci_debug_printf(5, "srv_suricata: suri_close_service: ENTER, g_suri_ready=%d, g_parent_pid=%d, current_pid=%d\n", g_suri_ready, g_parent_pid, current_pid);

    if (!g_suri_ready) {
        return;
    }
    g_suri_ready = 0;

    /* * CRITICAL CHECK: Only tear down threads and force exit if we are running 
     * inside the specific process context that initialized them.
     */
    if (current_pid == g_parent_pid) {
        ci_debug_printf(5, "srv_suricata: suri_close_service: Start Suricata shutdown in parent process, current_pid=%d\n", current_pid);

        ci_debug_printf(5, "srv_suricata: suri_close_service: EngineStop()\n");
        EngineStop();

        ci_debug_printf(5, "srv_suricata: suri_close_service: SuricataShutdown()\n");
        SuricataShutdown();

        /*
         * SuricataShutdown and the worker's SCTmThreadsSlotPacketLoopFinish
         * must run concurrently (see custom/main.c notes).  The pthread_join
         * here ensures the worker has finished before we return.
         */
        ci_debug_printf(5, "srv_suricata: suri_close_service: pthread_join()\n");
        pthread_join(g_worker_tid, NULL);

        ci_debug_printf(5, "srv_suricata: suri_close_service: GlobalsDestroy()\n");
        GlobalsDestroy();

        ci_debug_printf(5, "srv_suricata: suri_close_service: shutdown complete, current_pid=%d\n", current_pid);
    }
    else {
        /* * We are in the master parent process. The child has already exited, 
         * so we just clear our local flag status and return normally to let 
         * c-icap finalize its own master process shutdown sequence.
         */
        ci_debug_printf(5, "srv_suricata: suri_close_service: Bypass Suricata shutdown in child process, current_pid=%d\n", current_pid);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Per-request lifecycle
 * ═══════════════════════════════════════════════════════════════════════════ */

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

/* ─── internal helper: append bytes to the per-request body buffer ────── */

static int AppendToBodyBuf(struct suricata_req_data *d,
                           const char *buf, int len)
{
    if (!buf || len <= 0)
        return 0;

    /* Enforce the hard cap. */
    if (d->body_len >= SRV_SURICATA_MAX_BODY) {
        ci_debug_printf(4, "srv_suricata: body cap reached, dropping chunk\n");
        return 0;
    }
    if (d->body_len + len > SRV_SURICATA_MAX_BODY)
        len = SRV_SURICATA_MAX_BODY - d->body_len;

    /* Grow buffer if needed. */
    if (d->body_len + len > d->body_cap) {
        int new_cap = d->body_cap * 2;
        while (new_cap < d->body_len + len)
            new_cap *= 2;
        if (new_cap > SRV_SURICATA_MAX_BODY)
            new_cap = SRV_SURICATA_MAX_BODY;

        uint8_t *tmp = realloc(d->body_buf, new_cap);
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

/* ═══════════════════════════════════════════════════════════════════════════
 * suri_check_preview_handler
 *
 * Called after c-icap has received the ICAP preview block.
 * We inspect the preview bytes immediately, then signal CONTINUE so we keep
 * receiving the rest of the body via suri_io.
 * ═══════════════════════════════════════════════════════════════════════════ */

int suri_check_preview_handler(char *preview_data, int preview_data_len, ci_request_t *req)
{
    struct suricata_req_data *d = ci_service_data(req);

    ci_debug_printf(5, "srv_suricata: suri_check_preview_handler: ENTER, preview_data_len=%d\n", preview_data_len);

    /*
     * Unlock the response body so c-icap can stream it back to the client
     * while we process.  For a blocking/drop PoC you would remove this call.
     */
    ci_req_unlock_data(req);

    /* Store preview bytes in our accumulation buffer. */
    if (preview_data && preview_data_len > 0) {
        AppendToBodyBuf(d, preview_data, preview_data_len);

        /*
         * ── Suricata injection point #1: preview chunk ──────────────────
         *
         * If the preview already contains the entire body (ci_req_hasalldata)
         * we inject right here and never enter suri_io.
         */
        if (ci_req_hasalldata(req)) {
            ci_debug_printf(7, "srv_suricata: suri_check_preview_handler: Injecting %d bytes into Suricata\n", d->body_len);
            BuildAndInjectPacket(d->body_buf, d->body_len);
            d->eof = 1;
        }
    }

    /* Always continue — we never modify content in this PoC. */
    return CI_MOD_CONTINUE;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * suri_end_of_data_handler
 *
 * Called after all body data has been received.  This is where we perform
 * the final Suricata inspection pass on the fully accumulated buffer.
 * ═══════════════════════════════════════════════════════════════════════════ */

int suri_end_of_data_handler(ci_request_t *req)
{
    struct suricata_req_data *d = ci_service_data(req);

    ci_debug_printf(5, "srv_suricata: suri_end_of_data: ENTER, body_len=%d bytes\n", d->body_len);

    /*
     * ── Suricata injection point #2: full body ───────────────────────────
     *
     * Only inject if we haven't already done so in the preview handler
     * (i.e., when the body spanned multiple chunks via suri_io).
     */
    if (!d->eof && d->body_len > 0) {
        ci_debug_printf(5, "srv_suricata: suri_end_of_data: Injecting %d bytes into Suricata\n", d->body_len);
        BuildAndInjectPacket(d->body_buf, d->body_len);
    }

    d->eof = 1;
    return CI_MOD_DONE;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * suri_io — streaming IO callback
 *
 * Called repeatedly by c-icap while body data is in flight.
 *
 * Parameters (from c-icap ABI):
 *   wbuf / wlen  — buffer c-icap wants us to FILL for sending back to client
 *   rbuf / rlen  — buffer containing data READ from the client
 *   iseof        — non-zero when no more data follows
 *   req          — current ICAP request
 *
 * Because we are in detect-only (pass-through) mode, we echo rbuf → wbuf
 * unchanged, accumulating a copy in our body buffer for Suricata.
 * ═══════════════════════════════════════════════════════════════════════════ */

int suri_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof, ci_request_t *req)
{
    struct suricata_req_data *d = ci_service_data(req);
    int ret = CI_OK;

    ci_debug_printf(5, "srv_suricata: suri_io: ENTER rbuf=%p, wbuf=%p, rlen=%p, wlen=%p, *rlen=%d, *wlen=%d, iseof=%d, req=%p\n",
        rbuf ? rbuf : NULL, wbuf ? wbuf : NULL, rlen ? rlen : NULL, wlen ? wlen : NULL, rlen ? *rlen : 0, wlen ? *wlen : 0, iseof, req);

    if (rbuf && rlen && *rlen > 0) {
        ci_debug_printf(5, "srv_suricata: suri_io: AppendToBodyBuf %d bytes\n", *rlen);

        // BuildAndInjectPacket((const uint8_t *)rbuf, *rlen);
        AppendToBodyBuf(d, rbuf, *rlen);
    }

    if (wbuf && wlen && *wlen > 0) {
        if (d->sent_len < d->body_len) {
            int copy_len = (d->body_len - d->sent_len < *wlen) ? d->body_len - d->sent_len : *wlen;
            ci_debug_printf(5, "srv_suricata: suri_io: Send %d bytes to client\n", copy_len);
            memcpy(wbuf, d->body_buf + d->sent_len, copy_len);
            *wlen = copy_len;
            d->sent_len += copy_len;
        }
        else {
            *wlen = 0;
            ci_debug_printf(5, "srv_suricata: suri_io: No more data to send, set *wlen=0\n");
        }
    }

    if (wlen && *wlen == 0 && d->eof == 1) {
        ci_debug_printf(5, "srv_suricata: suri_io: Set EOF\n");
        *wlen = CI_EOF;
    }

    return ret;
}

int suri_cfg_mode(const char *directive, const char **argv, void *setdata)
{
    if (strcasecmp(argv[0], "disallow204") == 0)
        MODE= mode_disallow204;
    else {
        ci_debug_printf(1, "Unknown value '%s' for configuration parameter '%s'\n", argv[0], directive);
        return 0;
    }
    return 1;
}
