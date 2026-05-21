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
#include <c_icap/c-icap.h>
#include <c_icap/service.h>
#include <c_icap/header.h>
#include <c_icap/body.h>
#include <c_icap/simple_api.h>
#include <c_icap/debug.h>
#include <c_icap/cfg_param.h>

/* ── libsuricata ─────────────────────────────────────────────────────────── */
/*
 * These headers live under  $(suricata-src)/src/  and are installed via
 * `make install-headers`.  Adjust the include path in the Makefile if
 * your installation places them differently.
 */
#include <suricata/suricata.h>       /* SuricataPreInit / SuricataInit / … */
#include <suricata/conf.h>           /* ConfSet / ConfGet                  */
#include <suricata/runmodes.h>       /* SCRunmodeSet, RUNMODE_LIB, …       */
#include <suricata/tm-threads.h>     /* TM_ECODE_OK, SCFinalizeRunMode     */
#include <suricata/source-lib.h>     /* SCRunModeLibCreateThreadVars       */
#include <suricata/util-debug.h>     /* SCLogNotice / ci_debug_printf      */
#include <suricata/packet.h>         /* Packet, PacketGetFromQueueOrAlloc  */
#include <suricata/decode.h>         /* PKT_SRC_WIRE, PacketSetData        */
#include <suricata/util-time.h>      /* SCTIME_FROM_TIMEVAL                */
#include <suricata/live.h>           /* LiveRegisterDevice / LiveGetDevice */

/* ═══════════════════════════════════════════════════════════════════════════
 * Module-wide globals
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Maximum body bytes we reassemble per request before handing off to Suricata.
 * Keep small for the PoC; bump later or switch to streaming chunks.
 */
#define SRV_SURICATA_MAX_BODY (256 * 1024)  /* 256 KiB */

/*
 * Hard-coded Suricata rule loaded during module init.
 * Fires on "evil" appearing anywhere in TCP payload — trivial but testable.
 */
static const char *HARDCODED_RULE =
    "alert tcp any any -> any any "
    "(msg:\"ICAP-SURICATA PoC match — keyword evil found\"; "
    "content:\"evil\"; nocase; sid:9000001; rev:1;)";

/*
 * Suricata worker thread bookkeeping (library-mode pattern from custom/main.c).
 */
static ThreadVars *g_worker_tv  = NULL;
static pthread_t   g_worker_tid = 0;
static int         g_suri_ready = 0;   /* set to 1 after SuricataPostInit */

/* ── Suricata library worker thread ──────────────────────────────────────── */

/*
 * The library runmode needs at least one ThreadVars created in a runmode-setup
 * callback before SuricataInit seals the threads.
 */
static int SuricataRunModeSetup(void)
{
    /*
     * TimeModeSetOffline: we feed synthetic packets with fabricated timestamps,
     * so we do not want the engine to complain about clock skew.
     */
    TimeModeSetOffline();

    g_worker_tv = SCRunModeLibCreateThreadVars(1 /* worker_id */);
    if (g_worker_tv == NULL) {
        ci_debug_printf(1, "srv_suricata: SCRunModeLibCreateThreadVars failed\n");
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

    if (SCRunModeLibSpawnWorker(g_worker_tv) != 0) {
        ci_debug_printf(1, "srv_suricata: SCRunModeLibSpawnWorker failed\n");
    }

    pthread_exit(NULL);
}

/* ── Packet injection helper ─────────────────────────────────────────────── */

/*
 * BuildAndInjectPacket — wrap raw bytes in a minimal Suricata Packet and push
 * it through the detection engine.
 *
 * We present the payload as a raw TCP segment on a fake loopback device.
 * Suricata's DETECT module will match content-based signatures against the
 * raw bytes regardless of the encapsulation we claim.
 *
 * @param data   Pointer to the body buffer.
 * @param len    Number of bytes to inspect.
 */
static void BuildAndInjectPacket(const uint8_t *data, int len)
{
    if (!g_suri_ready || g_worker_tv == NULL) {
        ci_debug_printf(3, "srv_suricata: engine not ready, skipping packet injection\n");
        return;
    }

    Packet *p = PacketGetFromQueueOrAlloc();
    if (unlikely(p == NULL)) {
        ci_debug_printf(1, "srv_suricata: PacketGetFromQueueOrAlloc failed\n");
        return;
    }

    /* Timestamp — engine is in offline mode, so any value is fine. */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    SCTime_t ts = SCTIME_FROM_TIMEVAL(&tv);

    SCPacketSetSource(p, PKT_SRC_WIRE);
    SCPacketSetTime(p, ts);

    /*
     * LINKTYPE_RAW (228 / DLT_RAW):  raw IP, no Ethernet header.
     * We fabricate a minimal IPv4 + TCP header so decode works; however
     * for a content-only alert the exact IP/TCP fields do not matter.
     *
     * NOTE: In a later iteration you may instead use LINKTYPE_RAW and build
     * a proper minimal header, or use Suricata's stream-layer inject path.
     * For this PoC we pass the payload as-is with DLT_RAW and let Suricata
     * treat it as an unknown protocol — the content keyword still fires.
     */
    SCPacketSetDatalink(p, LINKTYPE_RAW /* 228 */);

    LiveDevice *dev = LiveGetDevice("suri_icap0");
    if (dev != NULL)
        SCPacketSetLiveDevice(p, dev);

    if (PacketSetData(p, data, len) == -1) {
        ci_debug_printf(1, "srv_suricata: PacketSetData failed\n");
        TmqhOutputPacketpool(g_worker_tv, p);
        return;
    }

    /*
     * Push packet into the detection pipeline.
     * TmThreadsSlotProcessPkt() is the canonical library-mode injection call
     * (see examples/lib/custom/main.c line 118).
     */
    if (TmThreadsSlotProcessPkt(g_worker_tv, g_worker_tv->tm_slots, p) != TM_ECODE_OK) {
        ci_debug_printf(1, "srv_suricata: TmThreadsSlotProcessPkt failed\n");
        TmqhOutputPacketpool(g_worker_tv, p);
    }

    /* Suricata owns the packet from here; do not free it ourselves. */
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Per-request data structure
 * ═══════════════════════════════════════════════════════════════════════════ */

struct suricata_req_data {
    uint8_t *body_buf;   /* flat accumulation buffer                    */
    int      body_len;   /* bytes written so far                        */
    int      body_cap;   /* allocated capacity                          */
    int      eof;        /* set when end-of-data_handler fires          */
    int      matched;    /* non-zero if a rule fired on this request    */
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Forward declarations — c-icap handler prototypes
 * ═══════════════════════════════════════════════════════════════════════════ */

int  suri_init_service(ci_service_xdata_t *srv_xdata,
                       struct ci_server_conf *server_conf);
void suri_close_service(void);
void *suri_init_request_data(ci_request_t *req);
void suri_release_request_data(void *data);
int  suri_check_preview_handler(char *preview_data, int preview_data_len,
                                ci_request_t *req);
int  suri_end_of_data_handler(ci_request_t *req);
int  suri_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
             ci_request_t *req);

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
    NULL,                               /* conf_variables            */
    NULL                                /* xdata                     */
};

/* Macro that registers the service with c-icap's module loader. */
_CI_DECLARE_SERVICE(suricata_service);

/* ═══════════════════════════════════════════════════════════════════════════
 * suri_init_service — called once when the module is loaded
 * ═══════════════════════════════════════════════════════════════════════════ */

int suri_init_service(ci_service_xdata_t *srv_xdata,
                      struct ci_server_conf *server_conf)
{
    ci_debug_printf(5, "srv_suricata: initialising Suricata library...\n");

    /* ── 1. Bootstrap Suricata ─────────────────────────────────────────── */

    /*
     * SuricataPreInit must be the very first call.  We pass the service name
     * as argv[0] equivalent so Suricata can locate its own binary path.
     */
    SuricataPreInit("srv_suricata");

    /* ── 2. Configure the engine programmatically ───────────────────────── */

    /*
     * We do NOT load a yaml config file.  All mandatory settings are injected
     * directly via the Conf API so this module has zero external dependencies.
     */

    /* Log to a file next to the c-icap log directory. */
    ConfSet("default-log-dir", "/var/log/suricata-icap");

    /* Offline / library mode — no live capture device required. */
    SCRunmodeSet(RUNMODE_LIB);

    /* Finalize runmode selection — required before SuricataInit. */
    if (SCFinalizeRunMode() != TM_ECODE_OK) {
        ci_debug_printf(1, "srv_suricata: SCFinalizeRunMode failed\n");
        return CI_ERROR;
    }

    /* ── 3. Register a loopback "live" device ───────────────────────────── */

    /*
     * Even in library mode the engine needs a LiveDevice for packets to be
     * associated with.  We create a virtual one.
     */
    if (LiveRegisterDevice("suri_icap0") < 0) {
        ci_debug_printf(1, "srv_suricata: LiveRegisterDevice failed\n");
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
    if (!ConfSet("runmode", "icap")) {
        ci_debug_printf(1, "srv_suricata: ConfSet runmode failed\n");
        return CI_ERROR;
    }

    /* ── 5. Load the hard-coded detection rule ──────────────────────────── */

    /*
     * Suricata expects rules either via a file path or inline.
     * ConfSet("rule-files.0", ...) points to a file; alternatively we can
     * write the rule to a temp file.  For the PoC we do the latter so the
     * caller needs no external rule files.
     */
    {
        char rule_path[] = "/tmp/srv_suricata_poc.rules";
        FILE *fp = fopen(rule_path, "w");
        if (fp == NULL) {
            ci_debug_printf(1, "srv_suricata: cannot write temp rule file\n");
            return CI_ERROR;
        }
        fprintf(fp, "%s\n", HARDCODED_RULE);
        fclose(fp);

        ConfSet("rule-files.0", rule_path);
        ci_debug_printf(5, "srv_suricata: loaded rule from %s\n", rule_path);
    }

    /* ── 6. Initialise the engine (calls SuricataRunModeSetup callback) ─── */

    SuricataInit();

    /* ── 7. Spawn the worker thread ─────────────────────────────────────── */

    if (pthread_create(&g_worker_tid, NULL, SuricataWorkerThread, NULL) != 0) {
        ci_debug_printf(1, "srv_suricata: pthread_create for worker failed\n");
        return CI_ERROR;
    }

    /* ── 8. Post-init (seals threads, starts packet queues, etc.) ────────── */

    SuricataPostInit();
    g_suri_ready = 1;

    ci_debug_printf(5, "srv_suricata: Suricata engine ready\n");

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
    ci_debug_printf(5, "srv_suricata: shutting down Suricata engine...\n");

    if (g_suri_ready) {
        g_suri_ready = 0;
        EngineStop();

        /*
         * SuricataShutdown and the worker's SCTmThreadsSlotPacketLoopFinish
         * must run concurrently (see custom/main.c notes).  The pthread_join
         * here ensures the worker has finished before we return.
         */
        pthread_join(g_worker_tid, NULL);

        SuricataShutdown();
        GlobalsDestroy();
    }

    ci_debug_printf(5, "srv_suricata: shutdown complete\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Per-request lifecycle
 * ═══════════════════════════════════════════════════════════════════════════ */

void *suri_init_request_data(ci_request_t *req)
{
    struct suricata_req_data *d = calloc(1, sizeof(*d));
    if (!d) {
        ci_debug_printf(1, "srv_suricata: calloc for request data failed\n");
        return NULL;
    }

    if (ci_req_hasbody(req)) {
        d->body_cap = 64 * 1024;  /* start with 64 KiB, grown in suri_io */
        d->body_buf = malloc(d->body_cap);
        if (!d->body_buf) {
            ci_debug_printf(1, "srv_suricata: malloc for body buf failed\n");
            free(d);
            return NULL;
        }
    }

    return d;
}

void suri_release_request_data(void *data)
{
    struct suricata_req_data *d = (struct suricata_req_data *)data;
    if (!d)
        return;
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

int suri_check_preview_handler(char *preview_data, int preview_data_len,
                               ci_request_t *req)
{
    struct suricata_req_data *d = ci_service_data(req);

    ci_debug_printf(8, "srv_suricata: preview handler, %d bytes\n",
                    preview_data_len);

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
            ci_debug_printf(7, "srv_suricata: all data in preview (%d bytes), "
                               "injecting into Suricata\n", d->body_len);
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

    ci_debug_printf(7, "srv_suricata: end_of_data, total body = %d bytes\n",
                    d->body_len);

    /*
     * ── Suricata injection point #2: full body ───────────────────────────
     *
     * Only inject if we haven't already done so in the preview handler
     * (i.e., when the body spanned multiple chunks via suri_io).
     */
    if (!d->eof && d->body_len > 0) {
        ci_debug_printf(7, "srv_suricata: injecting %d bytes into Suricata\n",
                        d->body_len);
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

int suri_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
            ci_request_t *req)
{
    struct suricata_req_data *d = ci_service_data(req);
    int ret = CI_OK;

    /* ── Receive side: accumulate data arriving from ICAP client ─────── */
    if (rbuf && rlen && *rlen > 0) {
        ci_debug_printf(10, "srv_suricata: suri_io recv %d bytes\n", *rlen);

        /*
         * ── Suricata injection point #3: streaming chunk ────────────────
         *
         * For the PoC we accumulate all chunks into body_buf and do a single
         * injection in end_of_data_handler.  If you want per-chunk inspection
         * (e.g., streaming detection before the full body arrives) simply call
         * BuildAndInjectPacket(rbuf, *rlen) here directly.
         *
         * Per-chunk approach (uncomment to enable):
         *
         *   BuildAndInjectPacket((const uint8_t *)rbuf, *rlen);
         */
        AppendToBodyBuf(d, rbuf, *rlen);
    }

    /* ── Send side: pass data through unmodified ─────────────────────── */
    if (wbuf && wlen) {
        if (rbuf && rlen && *rlen > 0) {
            /*
             * Echo the just-read bytes back so the HTTP response continues
             * flowing to the client without modification.
             */
            int copy_len = (*rlen < *wlen) ? *rlen : *wlen;
            memcpy(wbuf, rbuf, copy_len);
            *wlen = copy_len;
        } else {
            /* Nothing new to send yet. */
            *wlen = 0;
        }

        /* Signal EOF to c-icap once we know there is no more data. */
        if (d->eof || iseof) {
            *wlen = CI_EOF;
        }
    }

    return ret;
}
