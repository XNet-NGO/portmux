# portmux

Userspace TCP/UDP port forwarder for same-device loopback and cross-interface
relays. No TUN device, no VPN permission, no root required for the loopback and
source-bind cases. Built on the [hev-task-system](https://github.com/heiher/hev-task-system)
coroutine runtime — the same scheduler used by hev-socks5-tunnel — but with **no
lwIP**: it moves bytes between real kernel sockets. It also includes an optional
**SOCKS5 proxy** inbound (CONNECT + UDP ASSOCIATE) and an optional **encrypted
tunnel** (Noise `NoisePSK_NN`, IP + pre-shared key) — both reuse the same
socket-level relay and egress machinery, still with no lwIP and no TUN.

## Install

One-liner (Linux — detects your architecture, verifies the SHA-256, installs
the `portmux` CLI to `/usr/local/bin`, falling back to `~/.local/bin`):

```sh
curl -fsSL https://raw.githubusercontent.com/XNet-NGO/portmux/master/install.sh | sh
```

Pin a version or a target, or choose the install dir:

```sh
PORTMUX_VERSION=v0.5.0 curl -fsSL https://raw.githubusercontent.com/XNet-NGO/portmux/master/install.sh | sh
PORTMUX_TARGET=linux-x86_64-musl PORTMUX_PREFIX=$HOME/.local/bin \
  curl -fsSL https://raw.githubusercontent.com/XNet-NGO/portmux/master/install.sh | sh
```

Prefer to fetch the binary yourself? Each release publishes a per-target CLI
tarball plus `portmux-<ver>-cli-SHA256SUMS.txt`:

| Platform                | Asset                                   | Notes                                   |
| ----------------------- | --------------------------------------- | --------------------------------------- |
| Linux x86_64 (static)   | `portmux-<ver>-linux-x86_64-musl.tar.gz`| musl, fully static — runs on any Linux  |
| Linux x86_64 (glibc)    | `portmux-<ver>-linux-x86_64.tar.gz`     | dynamic; needs host-or-newer glibc      |
| Linux aarch64 / arm64   | `portmux-<ver>-linux-aarch64.tar.gz`    | glibc                                   |
| Linux armv7 (hard-float)| `portmux-<ver>-linux-armv7.tar.gz`      | glibc                                   |
| Linux riscv64           | `portmux-<ver>-linux-riscv64.tar.gz`    | glibc                                   |

```sh
# manual, e.g. arm64:
ver=v0.5.0; t=linux-aarch64
curl -fsSLO https://github.com/XNet-NGO/portmux/releases/download/$ver/portmux-$ver-$t.tar.gz
curl -fsSLO https://github.com/XNet-NGO/portmux/releases/download/$ver/portmux-$ver-cli-SHA256SUMS.txt
sha256sum -c --ignore-missing portmux-$ver-cli-SHA256SUMS.txt
tar -xzf portmux-$ver-$t.tar.gz portmux && sudo install -m0755 portmux /usr/local/bin/
```

portmux is **Linux-only** (epoll + an ELF coroutine context switch; no Windows/
macOS). On an unsupported architecture, [build from source](#build). The x86_64
one-liner installs the static musl build by default so it does not couple to the
host glibc version.

## Why not lwIP?

lwIP earns its place only when the input is raw IP packets from a TUN fd (that is
what hev-socks5-tunnel needs). A port forwarder already has layer-4 sockets on
both ends, so a second userspace TCP/IP stack would add latency and failure modes
for no benefit. portmux keeps the valuable parts of that lineage — the
`hev-task` coroutine model and the backpressure-aware splice — and drops lwIP.
The SOCKS5 inbound follows the same principle: it terminates the client on a
real kernel socket and splices to a real upstream socket, so it needs no
userspace IP stack.

## Use cases

- An MCP server on a fixed local port routed to a reverse-SSH forwarded port.
- A DAW app routed to a VST host app on another local port.
- Any "expose port A, forward to port B" need, optionally pinned to a chosen
  egress interface/network.

## Build

```sh
make            # builds bin/portmux (CLI) and bin/libportmux.a (static lib)
make test       # runs the in-process TCP+UDP end-to-end + idle-eviction tests
```

The hev-task-system runtime is vendored under `third-part/hev-task-system`
(MIT, pinned at upstream commit `935f3c1`), so a plain `git clone` is enough —
no submodule init required.

## Prebuilt artifacts

Each tagged release publishes prebuilt static libraries so an Android NDK (or
host) project can consume portmux without building it. Download the release
tarball or the per-ABI `.a` files from the
[Releases](https://github.com/XNet-NGO/portmux/releases) page.

Android (link **both** archives into your NDK target):

```
android/<abi>/libportmux.a
android/<abi>/libhev-task-system.a   # transitive dependency
```

ABIs: `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86` (built against NDK r28, API 21).
The public header is `include/portmux.h`. A host `linux-x86_64` build (static
lib + CLI) is included too.

Regenerate locally with:

```sh
ANDROID_NDK_HOME=/path/to/ndk ./scripts/build-release.sh   # -> dist/ + tarball
```

## CLI

```
portmux [-v] ROUTE [ROUTE ...]

ROUTE: PROTO:LADDR:LPORT:TADDR:TPORT[:EGRESS]
       socks:LADDR:LPORT[:EGRESS]     (SOCKS5 proxy, dynamic per-connection target)
  PROTO  tcp | udp
  EGRESS dev=IFNAME   (SO_BINDTODEVICE; needs CAP_NET_RAW/root)
         src=IP       (bind upstream socket to a local source IP)
```

Examples:

```sh
# MCP :39811 -> reverse-ssh local forward :2222 (loopback, no egress pin)
portmux tcp:127.0.0.1:39811:127.0.0.1:2222

# DAW -> VST, udp, pin egress to wlan0
portmux udp:127.0.0.1:9000:127.0.0.1:9001:dev=wlan0

# SOCKS5 proxy on :1080, every upstream connection pinned to wlan0
portmux socks:127.0.0.1:1080:dev=wlan0
```

## SOCKS5 proxy

`portmux_add_socks()` (CLI `socks:...`) opens a **SOCKS5 proxy** listener
instead of a fixed `A -> B` forward. The destination is chosen **per
connection** by the SOCKS client, not baked into the route.

- **Auth:** no-auth only (method `0x00`), per RFC 1928.
- **Commands:** `CONNECT` (TCP, spliced like a normal route) and
  `UDP ASSOCIATE` (a UDP relay socket is bound and datagrams are relayed to
  per-destination, egress-pinned upstream sockets). `BIND` is unsupported.
- **Address types:** IPv4, IPv6, and domain names.
- **Egress:** the route's `PortmuxEgress` is applied to **every** upstream
  socket the proxy opens, so egress pinning is per client connection. On
  Android the no-root path is `PORTMUX_EGRESS_CALLBACK` →
  `android_setsocknetwork()`, giving a **SOCKS proxy whose upstream is pinned to
  a chosen network (e.g. cellular) with no root and no TUN**.

A SOCKS5 proxy dials arbitrary destinations by design; expose it deliberately
(loopback bind, and in higher layers behind an explicit allow flag).

## Encrypted tunnel (NoisePSK_NN)

An optional **encrypted rendezvous tunnel** carries a plaintext TCP service
across an untrusted network with **no TUN, no root, and IP + pre-shared key
only** (no certificates, no PKI). It is a focused tunneling proxy — not a system
VPN — ideal for e.g. reaching a device's `adbd` from a remote box.

- **Crypto:** Noise pattern `NN` with a pre-shared key (`NoisePSK_NN`, i.e. the
  NNpsk0 construction): ephemeral X25519 (forward secrecy) authenticated by a
  32-byte PSK. Cipher is AES-256-GCM (hardware-accelerated on ARMv8) or
  ChaCha20-Poly1305; hash BLAKE2s. Vendored [noise-c](https://github.com/rweather/noise-c)
  reference backend (see `third-part/noise-c`), compiled into `libportmux.a`.
- **Shape (Scenario B — rendezvous):** the CLIENT makes ONE outbound encrypted
  connection to the SERVER (NAT/firewall friendly). The server exposes a local
  plaintext *bridge* port; a connection there is relayed, encrypted, to the
  client, which splices it to a local plaintext *target*.
- **Framing:** `[u16 length][Noise message]` for handshake and transport.
- **Egress:** the client's outbound leg honors `PortmuxEgress`, so the tunnel
  itself can be pinned to a chosen network (e.g. cellular) with no root.

```sh
# on the box (server): accept clients on :7000, expose an adb bridge on :5555
portmux tunnel-server 0.0.0.0:7000 127.0.0.1:5555 ~/.ssh/xnet-tunnel.psk

# on the phone/device (client): dial the box, splice to local adbd:5555
portmux tunnel-client BOX_IP:7000 127.0.0.1:5555 ~/.ssh/xnet-tunnel.psk

# then, on the box:
adb connect 127.0.0.1:5555     # adb speaks to the device's adbd over the tunnel
```

The PSK file is 32 raw bytes or 64 hex chars. A wrong PSK fails the handshake —
no data flows. v1 serves a single bridge connection per client session (enough
for one `adb` session); connection multiplexing is future work.

## Library API

See `include/portmux.h`. Minimal flow:

```c
Portmux *pm = portmux_new ();
portmux_add_route (pm, PORTMUX_PROTO_TCP, "127.0.0.1", 39811,
                   "127.0.0.1", 2222, NULL);
portmux_run (pm);        /* blocks on THIS thread until portmux_stop() */
portmux_destroy (pm);
```

`portmux_run` initializes the hev-task system, which is **thread-local**: call
`portmux_run` on the thread that will own the forwarder, and call `portmux_stop`
(from any thread or a signal handler) to shut it down.

## Egress selection (the "one interface to another" case)

Every upstream socket a route creates passes through `portmux_egress_apply`
before `connect`/`sendto`. Four policies (`PortmuxEgressKind`):

| Kind | How | Privilege |
|------|-----|-----------|
| `NONE` | default route / loopback | none |
| `SOURCE` | `bind()` to a local source IP | none |
| `DEVICE` | `SO_BINDTODEVICE` | CAP_NET_RAW / root |
| `CALLBACK` | your `PortmuxFdHook(fd, data)` runs before connect | none |

On Android, prefer `CALLBACK`: in the hook, call
`Network.bindSocket(fd)` (via JNI) to pin the upstream socket to a specific
`Network` without root. This is how you route to a non-default interface while
staying inside app sandbox rules and without touching the single system
`VpnService` TUN.

## Architecture

- One **bootstrap task** opens listeners and spawns one task per route plus an
  event task. (hev-task tasks that park on I/O must be spawned from within a
  running task, not queued from the plain main context.)
- **TCP**: `accept` → `connect` (egress applied) → `hev_task_io_splice`
  (bidirectional, ring-buffered, backpressure-aware — the slow side throttles
  the fast side, so no unbounded buffering).
- **UDP**: one listener socket; a flow table keyed by client source address;
  each flow owns a `connect()`ed upstream UDP socket and a task pumping
  target→client. A per-listener **sweeper task** evicts flows idle longer than
  `PM_UDP_IDLE_MS` (default 60s), checked every `PM_UDP_SWEEP_MS` (default 5s).
  Flows are freed only after their task fully exits (cooperative-scheduling-safe
  lifetime).
- **Shutdown**: `portmux_stop` writes a byte to an event socketpair; the event
  task sets `run=0` and **wakes every registered task** so tasks parked in
  `accept`/`recv` re-check and exit cleanly. (Setting a flag alone does not wake
  a task parked in WAITIO.)

## Notes / limits

- UDP idle flows are evicted by a per-listener sweeper (`PM_UDP_IDLE_MS` /
  `PM_UDP_SWEEP_MS`); override at compile time with `-D` for tighter timeouts.
- Max 64 routes, 1024 concurrent UDP flows, 256 KiB TCP splice buffer — all
  compile-time constants in `src/portmux.c`.
- Datagram buffers are heap-allocated (the 64 KiB coroutine stack cannot hold a
  64 KiB datagram buffer).

## License

MIT — see [LICENSE](LICENSE).

The vendored runtime under `third-part/hev-task-system` is also MIT
(see `third-part/hev-task-system/LICENSE`).
