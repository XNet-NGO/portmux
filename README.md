# portmux

Userspace TCP/UDP port forwarder for same-device loopback and cross-interface
relays. No TUN device, no VPN permission, no root required for the loopback and
source-bind cases. Built on the [hev-task-system](https://github.com/heiher/hev-task-system)
coroutine runtime — the same scheduler used by hev-socks5-tunnel — but with **no
lwIP and no SOCKS5**: it moves bytes between real kernel sockets.

## Why not lwIP?

lwIP earns its place only when the input is raw IP packets from a TUN fd (that is
what hev-socks5-tunnel needs). A port forwarder already has layer-4 sockets on
both ends, so a second userspace TCP/IP stack would add latency and failure modes
for no benefit. portmux keeps the valuable parts of that lineage — the
`hev-task` coroutine model and the backpressure-aware splice — and drops lwIP.

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

## CLI

```
portmux [-v] ROUTE [ROUTE ...]

ROUTE: PROTO:LADDR:LPORT:TADDR:TPORT[:EGRESS]
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
```

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
