# srv_suricata — c-icap × libsuricata PoC

> **Proof-of-Concept** — bare-bones data plumbing between a c-icap service
> module and the Suricata detection engine running in library mode.  
> Not production-ready; no content modification or blocking is performed.

---

## Directory layout

```
icap/
├── srv_suricata.c   — c-icap service module source
├── Makefile         — out-of-tree build (gcc, pkg-config, libsuricata-config)
└── README.md        — this file
```

---

## Prerequisites

### 1 · c-icap (server + development headers)

```bash
# Debian / Ubuntu
sudo apt install c-icap libc-icap-dev

# or build from source
git clone https://github.com/c-icap/c-icap-server.git
cd c-icap-server && ./configure --prefix=/usr && make && sudo make install
```

### 2 · libsuricata (built with `--enable-shared`)

```bash
git clone https://github.com/OISF/suricata.git
cd suricata
./autogen.sh
./configure --enable-shared --prefix=/usr
make -j$(nproc)
sudo make install
sudo make install-library     # installs libsuricata.so
sudo make install-headers     # installs headers under /usr/include/suricata
sudo ldconfig

# Verify the helper tool is on your PATH:
libsuricata-config --cflags
libsuricata-config --libs
```

---

## Build

```bash
cd icap/
make
# → produces  srv_suricata.so
```

To override install paths:

```bash
make CICAP_PREFIX=/opt/c-icap MODULES_DIR=/opt/c-icap/lib/c_icap
make install
```

---

## c-icap server configuration

Add the following to your `c-icap.conf`:

```
# Load the module
Module srv_suricata.so

# Bind the service to a URI path
Service suricata_service suricata
```

And configure your ICAP client (e.g. Squid) to forward requests to:

```
icap://<host>:1344/suricata
```

---

## Data-flow diagram

```
ICAP client (Squid / SSLproxy / E2Guardian)
        │
        │  ICAP REQMOD or RESPMOD request
        ▼
┌───────────────────────────────────────────────┐
│                  c-icap server                │
│                                               │
│  ① suri_check_preview_handler()               │
│     • receives up-to-4096-byte preview block  │
│     • appends bytes to body_buf               │
│     • if all data in preview → inject #1      │
│     • returns CI_MOD_CONTINUE                 │
│                                               │
│  ② suri_io()  [called in a loop]              │
│     • rbuf → AppendToBodyBuf()                │
│     • echoes rbuf → wbuf  (pass-through)      │
│     • optional per-chunk injection            │
│                                               │
│  ③ suri_end_of_data_handler()                 │
│     • injects full body_buf → Suricata        │
│     • returns CI_MOD_DONE                     │
└───────────────────────────────────────────────┘
        │
        │  BuildAndInjectPacket(body_buf, len)
        ▼
┌───────────────────────────────────────────────┐
│              libsuricata (RUNMODE_LIB)         │
│                                               │
│  PacketGetFromQueueOrAlloc()                  │
│  PacketSetData(p, body_buf, len)              │
│  TmThreadsSlotProcessPkt(g_worker_tv, ...)    │
│                                               │
│  Detection engine evaluates rule:             │
│    alert tcp any any -> any any               │
│    (content:"evil"; sid:9000001;)             │
│                                               │
│  → SCLogNotice() / alert log on match         │
└───────────────────────────────────────────────┘
```

---

## Three Suricata injection points

| # | Location | Condition |
|---|----------|-----------|
| 1 | `suri_check_preview_handler` | All body data fits inside the ICAP preview |
| 2 | `suri_end_of_data_handler` | Normal streaming case; full body accumulated |
| 3 | `suri_io` *(commented out)* | Per-chunk; uncomment for streaming detection |

---

## Testing

### Quick smoke test with `icap-client`

```bash
# Install
sudo apt install c-icap-client   # or build from c-icap source tree

# Send a benign request — expect no alert
echo -e "GET / HTTP/1.1\r\nHost: test.local\r\n\r\n" | \
    c-icap-client -s suricata -f /dev/stdin -req / -d 5

# Send a request containing the trigger keyword — expect Suricata alert
printf 'GET / HTTP/1.1\r\nHost: evil.local\r\nContent-Length:4\r\n\r\nevil' | \
    c-icap-client -s suricata -f /dev/stdin -req / -d 5
```

Watch `/var/log/suricata-icap/fast.log` (or `eve.json`) for the alert:

```
[**] [1:9000001:1] ICAP-SURICATA PoC match — keyword evil found [**]
```

### Manual curl-through-Squid

Configure Squid with `icap_service` pointing to `srv_suricata`, then:

```bash
curl -x http://squid-host:3128 http://evil-test.local/payload
```

---

## Known limitations / next steps

| Item | Status |
|------|--------|
| Detect-only — no block/drop | By design for PoC |
| Single worker thread | Sufficient for PoC; add pool for production |
| Body cap 256 KiB | Increase `SRV_SURICATA_MAX_BODY` or switch to streaming |
| Synthetic packet framing | Raw bytes injected without real IP/TCP headers |
| No YAML config | Engine configured programmatically via `ConfSet` |
| No thread-local Suricata context | Use `SCRunModeLibCreateThreadVars` per c-icap thread in production |
