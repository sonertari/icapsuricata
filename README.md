# srv_suricata — c-icap × libsuricata

> C-icap service with the Suricata detection engine running in library mode.

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
sudo apt install c-icap libicapapi-dev

# or build from source
git clone https://github.com/c-icap/c-icap-server.git
cd c-icap-server && ./configure && make && sudo make install
```

### 2 · libsuricata

```bash
git clone https://github.com/OISF/suricata.git
cd suricata
./configure
make -j$(nproc)
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
make CICAP_PREFIX=/opt/c-icap MODULES_DIR=/opt/c-icap/lib
make install
```

---

## c-icap server configuration

Add the following to your `c-icap.conf`:

```
# Load the module
Service suricata_service srv_suricata.so

# Disallow 204 responses if not desired
#suricata.Mode disallow204
```

And configure your ICAP client (e.g. SSLproxy) to forward requests to:

```
icap://<host>:1344/suricata
```
---

## Known limitations / next steps

| Item | Status |
|------|--------|
| Body cap 256 KiB | Increase `SRV_SURICATA_MAX_BODY` or switch to streaming |
| Synthetic packet framing | Raw bytes injected without real IP/TCP headers |
