# icapsuricata — c-icap × libsuricata

> A high-performance c-icap service integrating the Suricata intrusion detection engine running in library mode (`libsuricata`) to provide deep content inspection and inline threat prevention for proxy ecosystems.

## What It Does

`icapsuricata` is a service plugin for the `c-icap` server architecture. It bridges the gap between proxy infrastructure, such as [**SSLproxy**](https://github.com/sonertari/SSLproxy), and the **Suricata IPS/IDS engine**.

Unlike traditional setups, `icapsuricata` executes Suricata **in-line as a shared library (`libsuricata`)** within the proxy's execution context.

[This discussion at Suricata forum](https://forum.suricata.io/t/rethinking-the-sslproxy-suricata-integration-divert-mode-is-a-dead-end-for-h2-h3/6195) explains why `icapsuricata` is necessary for passing network context to Suricata and for deep content inspection of HTTP/2 and HTTP/3 traffic.

## How It Works (Under the Hood)

The core challenge of running an interface-based packet inspection engine inside a proxy service callback is state synchronization. For example, the proxy must pass network context to Suricata for correct application of IDS signatures. Also, web proxies pass linear data buffers, whereas Suricata expects raw network layers. `icapsuricata` solves such issues through the following primary pillars:

### Network Context: Extended ICAP
`icapsuricata` expects ICAP clients to provide network context via the following extended headers:

- `X-Client-IP`
- `X-Client-Port`
- `X-Server-IP`
- `X-Server-Port`
- `X-Proto`

It uses this network context when constructing emulated packets to be injected into Suricata.

`icapsuricata` returns the inspection result via the `X-Response-Info` header. For example:

```text
X-Response-Info: blocked
```

It also expects icap clients to echo back the `X-Response-Vars` header it injects into its responses to clients. `icapsuricata` uses the values in `X-Response-Vars` internally, to initialize client and server sequence numbers when injecting emulated packets into Suricata in RESPMOD. (The `X-Response-Vars` header may be removed in the future.)

```text
X-Response-Vars: 3493600807,3338221217
```

Currently, `icapsuricata` and the ICAP subsystem in `SSLproxy` support HTTP/1 only. But, the goal is to add support for other protocols, especially HTTP/2 and HTTP/3.

### Dual-Reader Circular Buffer (Zero Heap Churn)
To handle streaming payloads safely, the module manages memory via a high-performance, single-writer, dual-reader circular ring buffer. 
* **The Writer:** Drains volatile incoming raw buffers from `c-icap` (`rbuf`) immediately to enforce TCP window backpressure and avoid network stalls.
* **Reader 1 (Client Queue):** Safely drains data out to the outbound network socket block-by-block.
* **Reader 2 (Suricata Queue):** Accumulates data independently into optimal chunk boundaries (typically 4KB alignment) before staging it for packetization.
* **Space Reclamation:** Memory allocations are circular and strictly bound. Space is infinitely recycled the millisecond *both* readers have successfully advanced past a given index, completely eliminating runtime memory fragmentation (`realloc` loops).

### Low-Overhead Network Emulation Pipeline
Because `libsuricata` expects raw wire infrastructure, `icapsuricata` acts as a synthetic network tap. For every data transaction, it dynamically manufactures complete, valid, in-memory IPv4 and TCP frames containing appropriate hardware routing vectors, and TCP sequence space offsets.

* **Handshake Generation:** Upon session initialization, the module simulates mock TCP handshakes to initialize Suricata’s internal flow engine.
* **Secure Random ISN:** The module initializes sequence numbers securely using `/dev/urandom`.
* **Sequential Stream Tracking:** As data steps through the ring buffer, payloads are wrapped into standard `PUSH|ACK` packets.
* **State Finalization:** When the ICAP connection path flags an End-of-Data state (`iseof`), the module seamlessly injects sequentially correct `FIN|ACK` packet sweeps to cleanly close Suricata's internal state machine, forcing terminal application sweeps and releasing flow locks without hanging on idle timeouts.

### Progressive Mid-Stream Flushing
Instead of executing computationally heavy deep packet evaluation matrices on every micro-write, or conversely, waiting until the final connection close to discover an exploit, `icapsuricata` uses a balanced chunk flushing architecture. 

Data is packetized and evaluation cycles are triggered dynamically as chunks clear the ring buffer (e.g., every 4KB). This forces Suricata’s `StreamTcp` engine to regularly reassemble and push its content windows up to the Application Layer (`AppLayer`), allowing signatures leveraging keywords like `http.response_body` to match fragments split across multiple injections and stop active threats mid-transit.

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

## c-icap Server Configuration

Add the following to your `c-icap.conf`:

```ini
# Load the module
Service suricata_service srv_suricata.so

# Protocol mode: allow204|disallow204, defaults to allow204
# suricata.Mode disallow204

# ACK window size: 0-65535, defaults to 4000
# Setting to 0 disables ACK flushes in IDS mode
# Does not have any effect in IPS mode
suricata.ACKwindow 4000

# Preview size: 0-65535, defaults to 65535, max size allowed
suricata.Preview 1024

# Buffer size: 0-max unsigned integer, defaults to 65535, max preview size
# icapsuricata will not start if the buffer size is smaller than the preview size
# Setting to 0 effectively disables buffering, hence icapsuricata relies on c-icap's buffering
# c-icap's read and write buffer sizes are 4096 by default
suricata.BufSize 4096
```

### Protocol modes

* **`allow204` Mode (Preview Continuation):** The module inspects early HTTP headers and the initialization block via the preview handler. If the evaluation is inconclusive but a body exists, the module returns an ICAP `100 Continue` status code, explicitly forcing the ICAP client to stream the remaining body segments into the `suri_io` pipeline for complete inspection.
* **`disallow204` Mode:** Forces absolute structural encapsulation of the entire HTTP transmission stream.

### ACK window size

* **IDS mode:** If `libsuricata` is in IDS mode, `icapsuricata` injects cross-direction ACK packets mid-stream to act as evaluation/flushing triggers for Suricata, which prevents app-layer blindspots (due to internal optimizations like skipping frame inspection on non-state-changing payload updates). The ACK window option allows users to **control how frequently to flush the flow**. Setting ACKwindow to 0 disables ACK flushes in IDS mode too. If you want to configure the shortest window, set ACKwindow to 1.

* **IPS mode:** `icapsuricata` does not inject ACK packets if `libsuricata` is in IPS mode, as ACK flushing is not needed.

The initial **TCP handshake** emulation for session establishment and the final **FIN|ACK sweep** to cleanly finalize the flow are required and always executed in both IDS and IPS modes.

Note that ACK window size cannot be strictly applied, as it depends on many other factors like read buffer size that c-icap provides or content size in icap requests received at any time.

### Preview size

The Preview size is configured using the Preview option. PreviewSize is a standard c-icap directive that can be configured for all modules, but `icapsuricata` re-defines it to enforce the bufsize >= preview constraint.

Note that Preview is especially useful with the 204 mode.

### Buffer size

The BufSize option configures the size of dual ring buffer. `icapsuricata` does not start if the buffer size is smaller than the preview size. Setting BufSize to 0 disables buffering. And if the preview size is set to 0 too, `icapsuricata` completely relies on c-icap's buffering (more specifically, `suri_io` does not read rbuf until c-icap provides a wbuf > 0).

## Proxy Configuration

Configure your upstream ICAP client (e.g. **SSLproxy**) to forward requests or responses to:

```text
icap://<host>:1344/suricata
```

For example, you can use the following ICAP specification with SSLproxy:

```text
Icap icap://127.0.0.1:1344,suricata,suricata,open,open,10,1024,0,yes,no,X-Response-Vars
```
See the [icap branch](https://github.com/sonertari/SSLproxy/tree/icap) in the SSLproxy project for details.

## Licensing

`icapsuricata` interfaces directly with `libsuricata` via software API linking inside the execution stack. Please be aware of the following structural requirements regarding distribution:

* **c-icap** is licensed under the **LGPLv2.1**.
* **Suricata** is licensed under the **GPLv2**.

Because the GPL license model applies to combined works running within the same runtime process memory space, compilation or distribution of this module as a statically or dynamically linked runtime binary automatically qualifies the final artifact under **GPL** terms.
