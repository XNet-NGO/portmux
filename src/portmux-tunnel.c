/*
 ============================================================================
 Name        : portmux-tunnel.c
 Description : Userspace, no-TUN encrypted rendezvous tunnel (NoisePSK_NN).
 *
 * See include/portmux-tunnel.h for the design and wire framing. In short:
 *   - framing: [u16 BE length][Noise message] for both handshake and transport
 *   - crypto : NoisePSK_NN_25519_{AESGCM,ChaChaPoly}_BLAKE2s (ephemeral X25519
 *              + 32-byte PSK; forward secrecy; no certs)
 *   - relay  : once the handshake completes we own both fds and pump bytes:
 *              plaintext local side  <->  framed-AEAD remote side, in two
 *              cooperative tasks (no raw hev_task_io_splice, since one side is
 *              encrypted).
 ============================================================================
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>   /* TCP_MAXSEG */

#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>
#include <hev-task-system.h>

#include <noise/protocol.h>

#include "portmux.h"
#include "portmux-tunnel.h"
#include "portmux-log.h"
#include "portmux-addr.h"
#include "portmux-internal.h"

/* ───────────────────────── tunnel route storage ─────────────────────────
 * A tunnel is represented as an extra PortmuxRoute flavor. We reuse the route
 * struct's listen/target fields and tack the tunnel-specific bits onto a
 * heap-allocated PmTunnelCfg kept alive for the forwarder's lifetime. The
 * engine dispatches PORTMUX_PROTO_TUNNEL_* routes to the task entries here.
 */

typedef struct
{
    int is_server;                       /* 0 = client, 1 = server */
    char server_addr[128];               /* client: where to dial         */
    int server_port;
    char target_addr[128];               /* client: local plaintext target */
    int target_port;
    char bridge_addr[128];               /* server: laptop-facing listener */
    int bridge_port;
    unsigned char psk[PM_TUNNEL_PSK_LEN];
    PmTunnelCipher cipher;
    PortmuxEgress egress;
    int egress_valid;
    Portmux *owner;
    int listen_fd;                       /* server: encrypted-side listener;
                                            client: unused (-1) */
    int bridge_fd;                       /* server: bridge listener (-1 client) */
} PmTunnelCfg;

static const char *
cipher_name (PmTunnelCipher c)
{
    return (c == PM_TUNNEL_CIPHER_AESGCM)
             ? "NoisePSK_NN_25519_AESGCM_BLAKE2s"
             : "NoisePSK_NN_25519_ChaChaPoly_BLAKE2s";
}

/* ───────────────────────── MTU / MSS clamp ─────────────────────────
 * There is no TUN here, so "MTU 1280" is enforced at L4 as a TCP MSS clamp on
 * the CARRIER socket (the leg that crosses the real network). MTU 1280 maps to
 * MSS 1280 - 40(IPv6 hdr) - 20(TCP hdr) = 1220, which is also safe for IPv4
 * (1280 - 20 - 20 = 1240 >= 1220). Clamping the carrier avoids PMTU-blackhole
 * stalls on paths with a 1280 floor (e.g. some cellular/IPv6 transition links)
 * and bounds per-segment size. TCP_MAXSEG must be set before connect (client)
 * or on the accepted socket right after accept (server); the kernel still
 * honors a smaller peer-advertised MSS. */
#define PM_TUNNEL_MTU      1280
#define PM_TUNNEL_MSS_CLAMP (PM_TUNNEL_MTU - 60)   /* 1220: safe for v4 and v6 */

static void
pm_clamp_mss (int fd)
{
    int mss = PM_TUNNEL_MSS_CLAMP;
    if (setsockopt (fd, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof mss) < 0)
        PM_LOG_W ("tunnel: TCP_MAXSEG clamp to %d failed: %s", mss, strerror (errno));
}

/* ───────────────────────── carrier keepalive ─────────────────────────
 * The carrier is a long-lived TCP connection over a mobile network. A network
 * change (Wi-Fi<->cellular handoff, cell re-selection, NAT rebinding, IP
 * rotation) can leave the old socket in a "silently dead" state: the kernel
 * still believes it is ESTABLISHED and only tears it down after the full TCP
 * retransmit timeout (often minutes). TCP keepalive forces detection: after
 * [PM_TUNNEL_KA_IDLE_S] idle seconds, probe; if [PM_TUNNEL_KA_CNT] probes go
 * unanswered [PM_TUNNEL_KA_INTVL_S] apart, the kernel errors the socket, which
 * surfaces as carrier_dead and drives the client's reconnect. This is what
 * makes network-change recovery *timely* (the design cannot migrate a live TCP
 * socket across networks the way WireGuard's connectionless UDP roams; it must
 * detect-and-redial). ~25s to first detection. */
#define PM_TUNNEL_KA_IDLE_S  25   /* seconds idle before the first probe */
#define PM_TUNNEL_KA_INTVL_S 5    /* seconds between probes */
#define PM_TUNNEL_KA_CNT     3    /* dead after this many unanswered probes */
#define PM_TUNNEL_RECONNECT_DEBOUNCE_MS 3000  /* wait before redial after a drop */

static void
pm_set_keepalive (int fd)
{
    int on = 1;
    if (setsockopt (fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on) < 0) {
        PM_LOG_W ("tunnel: SO_KEEPALIVE failed: %s", strerror (errno));
        return;
    }
#ifdef TCP_KEEPIDLE
    int idle = PM_TUNNEL_KA_IDLE_S;
    setsockopt (fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof idle);
#endif
#ifdef TCP_KEEPINTVL
    int intvl = PM_TUNNEL_KA_INTVL_S;
    setsockopt (fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof intvl);
#endif
#ifdef TCP_KEEPCNT
    int cnt = PM_TUNNEL_KA_CNT;
    setsockopt (fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof cnt);
#endif
}


static int
io_read_full (Portmux *self, int fd, void *buf, size_t n)
{
    size_t got = 0;
    unsigned char *p = buf;
    while (got < n) {
        ssize_t r = hev_task_io_socket_recv (fd, p + got, n - got, 0,
                                             pm_run_yielder, self);
        if (r == -2 || r == 0)
            return -1;
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            return -1;
        }
        got += (size_t)r;
    }
    return 0;
}

static int
io_write_full (Portmux *self, int fd, const void *buf, size_t n)
{
    size_t sent = 0;
    const unsigned char *p = buf;
    while (sent < n) {
        ssize_t w = hev_task_io_socket_send (fd, p + sent, n - sent, 0,
                                             pm_run_yielder, self);
        if (w == -2)
            return -1;
        if (w <= 0) {
            if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                continue;
            return -1;
        }
        sent += (size_t)w;
    }
    return 0;
}

/* ───────────────────────── framed Noise messages ───────────────────────── */

/* Read one framed Noise message (u16 BE length + payload) into @buf (cap @cap).
   Returns the payload length, or -1 on error/eof/stop. */
static int
frame_read (Portmux *self, int fd, unsigned char *buf, size_t cap)
{
    unsigned char len_be[2];
    if (io_read_full (self, fd, len_be, 2) < 0)
        return -1;
    size_t len = ((size_t)len_be[0] << 8) | len_be[1];
    if (len > cap)
        return -1;
    if (len && io_read_full (self, fd, buf, len) < 0)
        return -1;
    return (int)len;
}

/* Write one framed Noise message. Returns 0 on success, -1 on error. */
static int
frame_write (Portmux *self, int fd, const unsigned char *buf, size_t len)
{
    unsigned char len_be[2];
    len_be[0] = (unsigned char)((len >> 8) & 0xff);
    len_be[1] = (unsigned char)(len & 0xff);
    if (io_write_full (self, fd, len_be, 2) < 0)
        return -1;
    if (len && io_write_full (self, fd, buf, len) < 0)
        return -1;
    return 0;
}

/* ───────────────────────── Noise handshake ─────────────────────────
 * Runs the NoisePSK_NN handshake over the framed stream. On success fills
 * @send/@recv with the split transport cipher states. Returns 0 / -1.
 */
static int
do_handshake (Portmux *self, int fd, int role,
              const unsigned char psk[PM_TUNNEL_PSK_LEN], PmTunnelCipher cipher,
              NoiseCipherState **send, NoiseCipherState **recv)
{
    NoiseHandshakeState *hs = NULL;
    unsigned char *msg;              /* 64 KiB — heap, NOT the 64 KiB coroutine stack */
    NoiseBuffer mb;
    int err, rc = -1;

    msg = malloc (PM_TUNNEL_MAX_NOISE_MSG);
    if (!msg)
        return -1;

    err = noise_handshakestate_new_by_name (&hs, cipher_name (cipher), role);
    if (err != NOISE_ERROR_NONE)
        goto out;
    noise_handshakestate_set_pre_shared_key (hs, psk, PM_TUNNEL_PSK_LEN);
    if (noise_handshakestate_start (hs) != NOISE_ERROR_NONE)
        goto out;

    for (;;) {
        int action = noise_handshakestate_get_action (hs);
        if (action == NOISE_ACTION_WRITE_MESSAGE) {
            noise_buffer_set_output (mb, msg, PM_TUNNEL_MAX_NOISE_MSG);
            if (noise_handshakestate_write_message (hs, &mb, NULL)
                != NOISE_ERROR_NONE)
                goto out;
            if (frame_write (self, fd, msg, mb.size) < 0)
                goto out;
        } else if (action == NOISE_ACTION_READ_MESSAGE) {
            int n = frame_read (self, fd, msg, PM_TUNNEL_MAX_NOISE_MSG);
            if (n < 0)
                goto out;
            noise_buffer_set_input (mb, msg, (size_t)n);
            if (noise_handshakestate_read_message (hs, &mb, NULL)
                != NOISE_ERROR_NONE)
                goto out; /* wrong PSK / tampered -> handshake fails here */
        } else if (action == NOISE_ACTION_SPLIT) {
            /* noise-c's split() returns the CipherStates from the LOCAL party's
               perspective: @send always encrypts our outbound and @recv
               decrypts our inbound, for BOTH roles (the library applies the
               initiator/responder swap internally). So no manual swap here. */
            if (noise_handshakestate_split (hs, send, recv) != NOISE_ERROR_NONE)
                goto out;
            rc = 0;
            goto out;
        } else {
            goto out; /* FAILED or unexpected */
        }
    }

out:
    noise_handshakestate_free (hs);
    free (msg);
    return rc;
}

/* ───────────────────────── stream-mux engine (B1) ─────────────────────────
 * One persistent Noise carrier multiplexes many streams. Each decrypted
 * transport frame is a mux record: [u8 type][u16 id][payload]. See
 * portmux-tunnel.h for the wire layout.
 *
 * Concurrency model (hev-task, single OS thread, cooperative):
 *   - ONE task owns the carrier fd AND every stream fd. hev-task binds each fd
 *     to exactly one task's reactor slot, so a shared-carrier + per-stream-task
 *     design cannot work (a stream task's write to the carrier would never wake
 *     since the carrier fd lives in the reader task). Therefore everything runs
 *     in a single mux loop that: (a) reassembles inbound carrier frames and
 *     dispatches them, and (b) round-robins reads of every stream socket,
 *     sealing each chunk as a DATA record to the carrier. Carrier writes are
 *     naturally serialized (one task), so records never interleave.
 */

typedef struct
{
    int fd;                      /* local socket, -1 = free slot            */
    /* pending carrier->local bytes awaiting write to fd (backpressure)     */
    unsigned char *pend;
    size_t pend_len, pend_sent;
    int want_close;              /* peer sent CLOSE; drain pend then close  */
} MuxStream;

typedef struct
{
    Portmux *self;
    int carrier_fd;
    NoiseCipherState *tx;        /* encrypts our outbound */
    NoiseCipherState *rx;        /* decrypts our inbound  */
    volatile int alive;          /* 0 once the carrier is torn down */

    MuxStream streams[PM_MUX_MAX_STREAMS];

    /* inbound carrier frame reassembly */
    unsigned char *inbuf;        /* PM_TUNNEL_MAX_NOISE_MSG */
    unsigned char ihdr[2];
    size_t ihdr_got;
    size_t ibody_len, ibody_got;
    int have_ilen;

    /* Carrier OUTPUT ring buffer: already-framed-and-sealed records waiting to
       be written to the carrier. A ring decouples record production (reads from
       local sockets) from carrier draining, so bulk bidirectional flow doesn't
       deadlock on a single pending record. */
    unsigned char *outring;      /* PM_MUX_OUT_RING bytes */
    size_t out_head, out_tail;   /* byte offsets; empty when head==tail */
    unsigned char *framebuf;     /* 2+PM_TUNNEL_MAX_NOISE_MSG scratch (heap) */

    /* client only: how to reach the local target for a new OPEN */
    char target_addr[128];
    int target_port;
    int is_server;
    unsigned int next_id;        /* server: id allocator */
    int pend_in;                 /* # streams with a pending inbound buffer */
    int accept_fd;               /* server: single public listener (-1 client) */
    int accept_port;             /* server: the public port (for logging) */
    /* server: credentials to run the carrier handshake inline when a Noise
       connection is peeked on the shared listener. */
    const unsigned char *psk;    /* PM_TUNNEL_PSK_LEN bytes */
    PmTunnelCipher cipher;
} MuxCtx;

#define PM_MUX_OUT_RING (1024 * 1024)   /* 1 MiB carrier output queue */

/* bytes currently queued in the output ring */
static size_t
outring_used (MuxCtx *m)
{
    return (m->out_head >= m->out_tail)
             ? (m->out_head - m->out_tail)
             : (PM_MUX_OUT_RING - m->out_tail + m->out_head);
}
static size_t
outring_free (MuxCtx *m)
{
    return PM_MUX_OUT_RING - 1 - outring_used (m);   /* -1: full/empty disambig */
}
/* append @n bytes to the ring (caller ensured room) */
static void
outring_push (MuxCtx *m, const unsigned char *p, size_t n)
{
    size_t first = PM_MUX_OUT_RING - m->out_head;
    if (first >= n) {
        memcpy (m->outring + m->out_head, p, n);
    } else {
        memcpy (m->outring + m->out_head, p, first);
        memcpy (m->outring, p + first, n - first);
    }
    m->out_head = (m->out_head + n) % PM_MUX_OUT_RING;
}

/* Seal (type,id,payload) and enqueue the framed record into the output ring.
   Returns 0 ok, -1 error, 1 ring-full (caller must back off and flush). */
static int
mux_queue_out (MuxCtx *m, unsigned char type, unsigned int id,
               const unsigned char *payload, size_t plen)
{
    /* build + seal the record into a scratch frame, then ring-append it */
    unsigned char *frame = m->framebuf;
    unsigned char *body = frame + 2;
    body[0] = type;
    body[1] = (unsigned char)((id >> 8) & 0xff);
    body[2] = (unsigned char)(id & 0xff);
    if (plen) memcpy (body + PM_MUX_HDR, payload, plen);
    size_t rec_len = PM_MUX_HDR + plen;

    NoiseBuffer mb;
    noise_buffer_set_inout (mb, body, rec_len, PM_TUNNEL_MAX_NOISE_MSG);
    if (noise_cipherstate_encrypt (m->tx, &mb) != NOISE_ERROR_NONE) return -1;
    frame[0] = (unsigned char)((mb.size >> 8) & 0xff);
    frame[1] = (unsigned char)(mb.size & 0xff);
    size_t total = mb.size + 2;

    if (outring_free (m) < total) return 1;          /* ring full: back off */
    outring_push (m, frame, total);
    return 0;
}

/* Drain the output ring to the carrier. Returns 1 progress, 0 blocked, -1 err,
   2 if nothing pending. */
static int
mux_flush_out (MuxCtx *m)
{
    if (m->out_head == m->out_tail) return 2;        /* empty */
    int did = 0;
    while (m->out_head != m->out_tail) {
        size_t contig = (m->out_head > m->out_tail)
                          ? (m->out_head - m->out_tail)
                          : (PM_MUX_OUT_RING - m->out_tail);
        ssize_t s = send (m->carrier_fd, m->outring + m->out_tail, contig, MSG_DONTWAIT);
        if (s > 0) { m->out_tail = (m->out_tail + (size_t)s) % PM_MUX_OUT_RING; did = 1; continue; }
        if (s < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return did ? 1 : 0;
        return -1;
    }
    return 1;
}

/* true if the output ring has room for a full max-size record */
static int
outring_has_room (MuxCtx *m)
{
    return outring_free (m) >= (size_t)(2 + PM_TUNNEL_MAX_NOISE_MSG);
}

/* Drain a stream's pending inbound (carrier->local) bytes to its socket. */
static int
mux_flush_stream (MuxCtx *m, int id)
{
    MuxStream *st = &m->streams[id];
    if (!st->pend || st->pend_len <= st->pend_sent) return 2;
    ssize_t s = send (st->fd, st->pend + st->pend_sent,
                      st->pend_len - st->pend_sent, MSG_DONTWAIT);
    if (s > 0) {
        st->pend_sent += (size_t)s;
        if (st->pend_sent >= st->pend_len) {
            free (st->pend); st->pend = NULL; st->pend_len = st->pend_sent = 0;
            m->pend_in--;
        }
        return 1;
    }
    if (s < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return -1;
    return 0;
}

/* Close + free a stream slot and detach its fd from the reactor. */
static void
mux_close_stream (MuxCtx *m, int id)
{
    MuxStream *st = &m->streams[id];
    if (st->fd >= 0) { hev_task_del_fd (hev_task_self (), st->fd); close (st->fd); st->fd = -1; }
    if (st->pend) { free (st->pend); st->pend = NULL; m->pend_in--; }
    st->pend_len = st->pend_sent = 0; st->want_close = 0;
}

/* Open a local target connection for a new OPEN (client side). Returns fd>=0. */
static int
mux_connect_target (MuxCtx *m)
{
    struct sockaddr_storage ss; socklen_t sl;
    int fam = portmux_resolve (m->target_addr, m->target_port, SOCK_STREAM, 0, &ss, &sl);
    if (fam < 0) return -1;
    int fd = hev_task_io_socket_socket (fam, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    hev_task_add_fd (hev_task_self (), fd, POLLIN | POLLOUT);
    if (hev_task_io_socket_connect (fd, (struct sockaddr *)&ss, sl,
                                    pm_run_yielder, m->self) < 0) {
        hev_task_del_fd (hev_task_self (), fd); close (fd); return -1;
    }
    pm_set_nodelay (fd);
    /* switch interest to read for the relay loop */
    hev_task_mod_fd (hev_task_self (), fd, POLLIN);
    return fd;
}

/* Dispatch one fully-received inbound carrier record. */
static void
mux_dispatch (MuxCtx *m, unsigned char type, unsigned int id,
              unsigned char *pl, size_t pn)
{
    if (id >= PM_MUX_MAX_STREAMS) return;
    MuxStream *st = &m->streams[id];

    if (type == PM_MUX_OPEN) {
        if (m->is_server) return;                 /* only client opens targets */
        PM_LOG_I ("tunnel-client: OPEN stream %u -> connecting %s:%d",
                  id, m->target_addr, m->target_port);
        int fd = mux_connect_target (m);
        if (fd < 0) { PM_LOG_W ("tunnel-client: target connect failed (stream %u)", id); mux_queue_out (m, PM_MUX_CLOSE, id, NULL, 0); return; }
        mux_close_stream (m, id);                 /* clear any stale slot */
        st->fd = fd;
        PM_LOG_I ("tunnel-client: stream %u target connected fd=%d", id, fd);
    } else if (type == PM_MUX_DATA) {
        if (st->fd < 0 || pn == 0) return;
        /* try immediate write; stash remainder as pending (gated so there is
           never more than one pending inbound buffer per stream — see pend_in) */
        ssize_t s = send (st->fd, pl, pn, MSG_DONTWAIT);
        size_t off = (s > 0) ? (size_t)s : 0;
        if (s < 0 && errno != EAGAIN && errno != EWOULDBLOCK) { mux_close_stream (m, id); mux_queue_out (m, PM_MUX_CLOSE, id, NULL, 0); return; }
        if (off < pn) {
            size_t rem = pn - off;
            unsigned char *np = malloc (rem);
            if (np) { memcpy (np, pl + off, rem);
                      if (st->pend) free (st->pend); else m->pend_in++;
                      st->pend = np; st->pend_len = rem; st->pend_sent = 0; }
        }
    } else if (type == PM_MUX_CLOSE) {
        if (st->fd >= 0) st->want_close = 1;      /* drain pend, then close */
    }
}

/* The unified mux loop: one task, owns carrier + all stream fds. */
static int mux_server_open (MuxCtx *m, int fd);   /* fwd */
static int peek_is_carrier (Portmux *self, int fd); /* fwd */
static void
mux_run (MuxCtx *m)
{
    unsigned char *rbuf = malloc (PM_TUNNEL_MAX_PLAINTEXT);
    m->inbuf  = malloc (PM_TUNNEL_MAX_NOISE_MSG);
    m->outring = malloc (PM_MUX_OUT_RING);
    m->framebuf = malloc (2 + PM_TUNNEL_MAX_NOISE_MSG);
    m->out_head = m->out_tail = 0;
    if (!rbuf || !m->inbuf || !m->outring || !m->framebuf) goto out;

    if (m->carrier_fd >= 0)
        hev_task_add_fd (hev_task_self (), m->carrier_fd, POLLIN | POLLOUT);
    if (m->is_server && m->accept_fd >= 0)
        hev_task_add_fd (hev_task_self (), m->accept_fd, POLLIN);

    while (m->alive && m->self->run) {
        int progress = 0;

        /* 0. server: accept connections on the SINGLE public listener and
              classify each by peeking (carrier 0x0030 vs adb/data client). */
        if (m->is_server && m->accept_fd >= 0 && outring_has_room (m)) {
            for (int b = 0; b < 4; b++) {
                struct sockaddr_storage ap; socklen_t al = sizeof ap;
                int afd = accept (m->accept_fd, (struct sockaddr *)&ap, &al);
                if (afd < 0) break;
                pm_set_nodelay (afd);
                int kind = peek_is_carrier (m->self, afd);
                if (kind < 0) { close (afd); continue; }
                if (kind == 1) {
                    /* carrier connection: clamp MSS, run responder handshake */
                    NoiseCipherState *tx = NULL, *rx = NULL;
                    pm_clamp_mss (afd);   /* MTU 1280 (MSS 1220) on the carrier */
                    pm_set_keepalive (afd); /* ~25s dead-path detection */
                    hev_task_add_fd (hev_task_self (), afd, POLLIN | POLLOUT);
                    if (do_handshake (m->self, afd, NOISE_ROLE_RESPONDER,
                                      m->psk, m->cipher, &tx, &rx) < 0) {
                        PM_LOG_W ("tunnel-server: carrier handshake rejected (bad PSK?)");
                        hev_task_del_fd (hev_task_self (), afd); close (afd);
                        continue;
                    }
                    /* replace any prior carrier (phone reconnected) */
                    if (m->carrier_fd >= 0) {
                        hev_task_del_fd (hev_task_self (), m->carrier_fd);
                        close (m->carrier_fd);
                        if (m->tx) noise_cipherstate_free (m->tx);
                        if (m->rx) noise_cipherstate_free (m->rx);
                        for (int id = 0; id < PM_MUX_MAX_STREAMS; id++)
                            if (m->streams[id].fd >= 0) mux_close_stream (m, id);
                        m->out_head = m->out_tail = 0;
                        m->ihdr_got = 0; m->have_ilen = 0;
                    }
                    m->carrier_fd = afd; m->tx = tx; m->rx = rx;
                    hev_task_mod_fd (hev_task_self (), afd, POLLIN | POLLOUT);
                    PM_LOG_I ("tunnel-server: carrier up (single-port :%d)",
                              m->accept_port);
                    progress = 1;
                    break;                         /* re-enter loop with carrier */
                }
                if (m->carrier_fd < 0) {
                    PM_LOG_W ("tunnel-server: adb client but no carrier yet; dropping");
                    close (afd);
                    continue;
                }
                mux_server_open (m, afd);
                progress = 1;
                if (!outring_has_room (m)) break;
            }
        }

        /* no carrier yet: nothing else to do this iteration */
        if (m->carrier_fd < 0) {
            if (!progress) hev_task_yield (HEV_TASK_WAITIO);
            else hev_task_yield (HEV_TASK_YIELD);
            continue;
        }

        /* 1. drain the carrier output ring */
        int fo = mux_flush_out (m);
        if (fo < 0) goto carrier_dead;   /* carrier write error: drop carrier,
                                            keep the listener (server) / reconnect (client) */
        if (fo == 1) progress = 1;

        /* 2. read inbound carrier frames and dispatch. This MUST NOT be gated
              on outbound ring space: inbound DATA is written to local sockets
              (stashed as per-stream pend on backpressure, no ring needed), so
              gating it on the outbound ring would deadlock when the uplink is
              backed up (return traffic could never drain). */
        {
            for (int budget = 0; budget < 16; budget++) {
                /* Don't pull a new frame while any stream still has undelivered
                   inbound bytes: a DATA frame for that stream would overwrite
                   its pend. Drain (step 3) first. */
                if (m->pend_in > 0) break;
                while (m->ihdr_got < 2) {
                    ssize_t r = recv (m->carrier_fd, m->ihdr + m->ihdr_got, 2 - m->ihdr_got, MSG_DONTWAIT);
                    if (r > 0) { m->ihdr_got += (size_t)r; progress = 1; }
                    else if (r == 0) goto carrier_dead;
                    else if (errno == EAGAIN || errno == EWOULDBLOCK) goto read_done;
                    else goto carrier_dead;
                }
                if (!m->have_ilen) {
                    m->ibody_len = ((size_t)m->ihdr[0] << 8) | m->ihdr[1];
                    m->ibody_got = 0; m->have_ilen = 1;
                    if (m->ibody_len == 0 || m->ibody_len > PM_TUNNEL_MAX_NOISE_MSG) goto carrier_dead;
                }
                while (m->ibody_got < m->ibody_len) {
                    ssize_t r = recv (m->carrier_fd, m->inbuf + m->ibody_got, m->ibody_len - m->ibody_got, MSG_DONTWAIT);
                    if (r > 0) { m->ibody_got += (size_t)r; progress = 1; }
                    else if (r == 0) goto carrier_dead;
                    else if (errno == EAGAIN || errno == EWOULDBLOCK) goto read_done;
                    else goto carrier_dead;
                }
                NoiseBuffer mb;
                noise_buffer_set_inout (mb, m->inbuf, m->ibody_len, PM_TUNNEL_MAX_NOISE_MSG);
                m->ihdr_got = 0; m->have_ilen = 0;
                if (noise_cipherstate_decrypt (m->rx, &mb) != NOISE_ERROR_NONE) goto carrier_dead;
                if (mb.size >= PM_MUX_HDR) {
                    unsigned char type = m->inbuf[0];
                    unsigned int id = ((unsigned int)m->inbuf[1] << 8) | m->inbuf[2];
                    mux_dispatch (m, type, id, m->inbuf + PM_MUX_HDR, mb.size - PM_MUX_HDR);
                }
                if (m->pend_in > 0) break;   /* a stream backpressured: drain first */
            }
        }
    read_done:

        /* 3. per-stream: flush pending local writes, then read local->carrier */
        for (int id = 0; id < PM_MUX_MAX_STREAMS; id++) {
            MuxStream *st = &m->streams[id];
            if (st->fd < 0) continue;

            int fs = mux_flush_stream (m, id);
            if (fs == 1) progress = 1;
            else if (fs < 0) { mux_close_stream (m, id); mux_queue_out (m, PM_MUX_CLOSE, id, NULL, 0); continue; }

            if (st->want_close && (!st->pend || st->pend_len <= st->pend_sent)) {
                mux_close_stream (m, id);
                continue;
            }
            if (st->pend) continue;              /* don't read more until drained */
            if (!outring_has_room (m)) continue; /* ring full: back off reading */

            ssize_t r = recv (st->fd, rbuf, PM_TUNNEL_MAX_PLAINTEXT - PM_MUX_HDR, MSG_DONTWAIT);
            if (r > 0) {
                int q = mux_queue_out (m, PM_MUX_DATA, (unsigned int)id, rbuf, (size_t)r);
                if (q < 0) { mux_close_stream (m, id); }
                progress = 1;
            } else if (r == 0) {
                mux_close_stream (m, id);
                mux_queue_out (m, PM_MUX_CLOSE, (unsigned int)id, NULL, 0);
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                mux_close_stream (m, id);
                mux_queue_out (m, PM_MUX_CLOSE, (unsigned int)id, NULL, 0);
            }
        }

        if (!progress)
            hev_task_yield (HEV_TASK_WAITIO);
        else
            hev_task_yield (HEV_TASK_YIELD);
        continue;

    carrier_dead:
        if (m->is_server) {
            /* The phone's carrier dropped. Keep the single public listener up
               and wait for the phone to reconnect; tear down this carrier's
               state and streams but do NOT exit the server. */
            PM_LOG_I ("tunnel-server: carrier down; awaiting phone reconnect on :%d",
                      m->accept_port);
            hev_task_del_fd (hev_task_self (), m->carrier_fd);
            close (m->carrier_fd); m->carrier_fd = -1;
            if (m->tx) { noise_cipherstate_free (m->tx); m->tx = NULL; }
            if (m->rx) { noise_cipherstate_free (m->rx); m->rx = NULL; }
            for (int id = 0; id < PM_MUX_MAX_STREAMS; id++)
                if (m->streams[id].fd >= 0) mux_close_stream (m, id);
            m->out_head = m->out_tail = 0;
            m->ihdr_got = 0; m->have_ilen = 0;
            continue;                     /* keep serving the listener */
        }
        break;                            /* client: exit; task reconnects */
    }

out:
    m->alive = 0;
    for (int id = 0; id < PM_MUX_MAX_STREAMS; id++)
        if (m->streams[id].fd >= 0) mux_close_stream (m, id);
    if (m->is_server && m->accept_fd >= 0)
        hev_task_del_fd (hev_task_self (), m->accept_fd);
    if (m->carrier_fd >= 0)
        hev_task_del_fd (hev_task_self (), m->carrier_fd);
    free (rbuf); free (m->inbuf); free (m->outring); free (m->framebuf);
    m->inbuf = NULL; m->outring = NULL; m->framebuf = NULL;
}

/* Server: register a new adb client as stream @id (allocate, OPEN, add fd). */
static int
mux_server_open (MuxCtx *m, int fd)
{
    unsigned int id = 0; int found = 0;
    for (unsigned int k = 0; k < PM_MUX_MAX_STREAMS; k++) {
        unsigned int cand = (m->next_id + k) % PM_MUX_MAX_STREAMS;
        if (cand == 0) continue;
        if (m->streams[cand].fd < 0) { id = cand; found = 1; break; }
    }
    if (!found) { close (fd); return -1; }
    m->next_id = (id + 1) % PM_MUX_MAX_STREAMS;
    pm_set_nodelay (fd);
    hev_task_add_fd (hev_task_self (), fd, POLLIN);
    m->streams[id].fd = fd;
    if (mux_queue_out (m, PM_MUX_OPEN, id, NULL, 0) < 0) { mux_close_stream (m, (int)id); return -1; }
    PM_LOG_I ("tunnel-server: adb client -> stream %u (OPEN)", id);
    return (int)id;
}

/* Peek the first 2 bytes of a freshly-accepted connection to classify it.
 * The Noise carrier is NoisePSK_NN (NNpsk0): the PSK is mixed before the first
 * message, so even the initiator's first frame (the 32-byte X25519 ephemeral)
 * carries a 16-byte AEAD tag -> 48 bytes, i.e. the u16 length prefix is 0x0030.
 * Anything else (adb's "CNXN" = 0x43.., or any other client) is an adb/data
 * client to be muxed. Returns 1=carrier, 0=adb-client, -1=error/closed.
 * Blocks (cooperatively) until >=2 bytes are peekable. */
#define PM_CARRIER_FIRST_LEN (PM_TUNNEL_PSK_LEN + PM_TUNNEL_AEAD_TAG) /* 0x0030 */
#define PM_PEEK_TIMEOUT_MS 1500   /* carrier speaks immediately; silence => data client */
static int
peek_is_carrier (Portmux *self, int fd)
{
    unsigned char b[2];
    unsigned long start = pm_mono_ms ();
    for (;;) {
        ssize_t r = recv (fd, b, 2, MSG_PEEK);
        if (r >= 2) break;
        if (r == 0) return -1;                 /* closed before 2 bytes */
        if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return -1;
        if (!self->run) return -1;
        /* The carrier (Noise initiator) sends its 48-byte handshake frame
           immediately. If we see no (or <2) bytes within the window, this is a
           client that waits to be spoken to first — classify it as a data/adb
           client so server-speaks-first protocols (e.g. the echo banner) work. */
        if (pm_mono_ms () - start > PM_PEEK_TIMEOUT_MS)
            return 0;
        hev_task_sleep (20);   /* short poll so the timeout can fire on silence */
    }
    return (b[0] == 0x00 && b[1] == PM_CARRIER_FIRST_LEN) ? 1 : 0;
}

/* ───────────────────────── client ─────────────────────────
 * Dial the server (egress-pinned), handshake as initiator, connect the local
 * plaintext target, and relay. Reconnect/backoff is left to the caller layer;
 * v1 runs a single session per task invocation and exits on teardown.
 */
static void
tunnel_client_task (void *data)
{
    PortmuxRoute *route = data;
    PmTunnelCfg *cfg = (PmTunnelCfg *)route->egress.callback_data; /* stash */
    Portmux *self = cfg->owner;
    PmTaskNode node;
    struct sockaddr_storage ss;
    socklen_t sslen;
    int family, srv_fd = -1, tgt_fd = -1;
    NoiseCipherState *tx = NULL, *rx = NULL;

    pm_task_register (self, &node);

    while (self->run) {
        /* Resolve + dial the rendezvous server (encrypted side). */
        family = portmux_resolve (cfg->server_addr, cfg->server_port,
                                  SOCK_STREAM, 0, &ss, &sslen);
        if (family < 0) { hev_task_sleep (2000); continue; }

        {
            PortmuxRoute tmp;
            memset (&tmp, 0, sizeof tmp);
            tmp.egress = cfg->egress;
            tmp.egress_valid = cfg->egress_valid;
            srv_fd = pm_make_upstream_fd (&tmp, family, SOCK_STREAM);
        }
        if (srv_fd < 0) { hev_task_sleep (2000); continue; }
        pm_clamp_mss (srv_fd);        /* MTU 1280 (MSS 1220) on the carrier */
        pm_set_keepalive (srv_fd);    /* ~25s dead-path detection for handoffs */
        hev_task_add_fd (hev_task_self (), srv_fd, POLLIN | POLLOUT);
        if (hev_task_io_socket_connect (srv_fd, (struct sockaddr *)&ss, sslen,
                                        pm_run_yielder, self) < 0) {
            PM_LOG_I ("tunnel-client: connect %s:%d failed", cfg->server_addr,
                      cfg->server_port);
            goto reconnect;
        }
        pm_set_nodelay (srv_fd);

        if (do_handshake (self, srv_fd, NOISE_ROLE_INITIATOR, cfg->psk,
                          cfg->cipher, &tx, &rx) < 0) {
            PM_LOG_W ("tunnel-client: handshake failed (PSK/cipher mismatch?)");
            goto reconnect;
        }
        PM_LOG_I ("tunnel-client: tunnel up to %s:%d (mux carrier)",
                  cfg->server_addr, cfg->server_port);

        /* B1: this is a persistent MUX carrier. Each inbound OPEN opens a fresh
           connection to the local target (adbd); the single mux loop owns the
           carrier and all stream fds and runs until the carrier dies. */
        {
            MuxCtx m;
            memset (&m, 0, sizeof m);
            m.self = self; m.carrier_fd = srv_fd; m.tx = tx; m.rx = rx;
            m.alive = 1; m.is_server = 0; m.accept_fd = -1;
            for (int i = 0; i < PM_MUX_MAX_STREAMS; i++) m.streams[i].fd = -1;
            snprintf (m.target_addr, sizeof m.target_addr, "%s", cfg->target_addr);
            m.target_port = cfg->target_port;
            mux_run (&m);
        }
        PM_LOG_I ("tunnel-client: carrier ended; will reconnect");

reconnect:
        if (tx) { noise_cipherstate_free (tx); tx = NULL; }
        if (rx) { noise_cipherstate_free (rx); rx = NULL; }
        if (tgt_fd >= 0) { hev_task_del_fd (hev_task_self (), tgt_fd); close (tgt_fd); tgt_fd = -1; }
        if (srv_fd >= 0) { hev_task_del_fd (hev_task_self (), srv_fd); close (srv_fd); srv_fd = -1; }
        if (!self->run)
            break;
        /* 3s reconnect debounce: after a carrier drop (often a network change),
           wait before redialing so a flapping handoff doesn't produce a storm
           of short-lived carriers (each of which resets the server's streams).
           Keepalive already bounds how long a dead path lingers before we get
           here (~25s), so this debounce adds responsiveness without churn. */
        hev_task_sleep (PM_TUNNEL_RECONNECT_DEBOUNCE_MS);
    }

    pm_task_unregister (self, &node);
}

/* ───────────────────────── server ─────────────────────────
 * Single-session, single-task rendezvous server. One task owns BOTH listeners
 * (encrypted client side + plaintext bridge). Each iteration:
 *   1. accept + handshake exactly one client,
 *   2. accept exactly one bridge (laptop adb) connection,
 *   3. relay until either side closes, then loop for the next client.
 *
 * Only one client/bridge pair is live at a time (v1), so there is no
 * fd-ownership race and the bridge is never paired with a stale client. A
 * client that connects while a relay is in progress waits in the listen
 * backlog and is picked up on the next iteration. (Client-side reconnect churn
 * is bounded by the app, which keeps one long-lived tunnel per enabled route.)
 */
/* B1 single-port server: ONE public listener (cfg->listen_fd). Every accepted
 * connection is classified by peeking its first 2 bytes:
 *   - Noise carrier (len prefix 0x0020) -> the phone's persistent encrypted
 *     carrier; run the responder handshake and hold it.
 *   - anything else                     -> an adb client; assign a stream-id
 *     and mux it over the live carrier.
 * So the box exposes exactly one port (e.g. :2222) that is BOTH the phone's
 * dial-in AND the adb endpoint (`adb connect box:2222`). No bridge, no second
 * port. mux_run owns the listener, the carrier, and all stream fds in one task
 * (hev-task binds each fd to one task's reactor).
 */
static void
tunnel_server_task (void *data)
{
    PortmuxRoute *route = data;
    PmTunnelCfg *cfg = (PmTunnelCfg *)route->egress.callback_data;
    Portmux *self = cfg->owner;
    PmTaskNode node;

    pm_task_register (self, &node);
    PM_LOG_I ("tunnel-server: single-port %s:%d (carrier + adb, peek-demux)",
              cfg->server_addr, cfg->server_port);

    MuxCtx m;
    memset (&m, 0, sizeof m);
    m.self = self;
    m.carrier_fd = -1;                 /* no carrier until the phone dials in */
    m.alive = 1; m.is_server = 1; m.next_id = 1;
    m.accept_fd = cfg->listen_fd;      /* the single public listener           */
    m.accept_port = cfg->server_port;
    m.psk = cfg->psk; m.cipher = cfg->cipher;
    for (int i = 0; i < PM_MUX_MAX_STREAMS; i++) m.streams[i].fd = -1;

    /* Runs until engine shutdown; internally establishes/replaces the carrier
       and muxes adb clients. Never returns until self->run == 0. */
    mux_run (&m);

    close (cfg->listen_fd);
    pm_task_unregister (self, &node);
}

/* ───────────────────────── public registration ─────────────────────────
 * Tunnel routes reuse the engine's route array; we smuggle the PmTunnelCfg via
 * route->egress.callback_data and mark the proto so bootstrap dispatches here.
 * portmux.c calls pm_tunnel_listen_task()/pm_tunnel_client_task() for us.
 */

/* Entry points the engine bootstrap dispatches to (declared in internal.h). */
void
pm_tunnel_server_entry (void *route)
{
    tunnel_server_task (route);
}

void
pm_tunnel_client_entry (void *route)
{
    tunnel_client_task (route);
}

/* Open the server listeners (encrypted + bridge) before spawning the task.
   Returns 0 on success. Called from portmux.c open phase. */
int
pm_tunnel_open_server (PortmuxRoute *route)
{
    PmTunnelCfg *cfg = (PmTunnelCfg *)route->egress.callback_data;
    struct sockaddr_storage ss;
    socklen_t sslen;
    int family, fd, on = 1;

    /* encrypted-side listener */
    family = portmux_resolve (cfg->server_addr, cfg->server_port, SOCK_STREAM,
                              1, &ss, &sslen);
    if (family < 0)
        return -1;
    fd = hev_task_io_socket_socket (family, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    if (bind (fd, (struct sockaddr *)&ss, sslen) < 0 || listen (fd, 16) < 0) {
        PM_LOG_E ("tunnel-server: bind/listen %s:%d: %s", cfg->server_addr,
                  cfg->server_port, strerror (errno));
        close (fd);
        return -1;
    }
    cfg->listen_fd = fd;
    route->listen_fd = fd;

    /* Single-port mode (B1 peek-demux): if no separate public port is given,
       the one listener above serves BOTH the carrier and adb clients. */
    if (cfg->bridge_port <= 0) {
        cfg->bridge_fd = -1;
        return 0;
    }

    /* (legacy) separate public adb listener */
    family = portmux_resolve (cfg->bridge_addr, cfg->bridge_port, SOCK_STREAM,
                              1, &ss, &sslen);
    if (family < 0) { close (fd); return -1; }
    fd = hev_task_io_socket_socket (family, SOCK_STREAM, 0);
    if (fd < 0) { close (cfg->listen_fd); return -1; }
    setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    if (bind (fd, (struct sockaddr *)&ss, sslen) < 0 || listen (fd, 16) < 0) {
        PM_LOG_E ("tunnel-server: bridge bind/listen %s:%d: %s",
                  cfg->bridge_addr, cfg->bridge_port, strerror (errno));
        close (fd);
        close (cfg->listen_fd);
        return -1;
    }
    cfg->bridge_fd = fd;
    return 0;
}

static PmTunnelCfg *
alloc_cfg (Portmux *self)
{
    PmTunnelCfg *cfg = calloc (1, sizeof *cfg);
    if (cfg) { cfg->owner = self; cfg->listen_fd = -1; cfg->bridge_fd = -1; }
    return cfg;
}

/* Register a tunnel route in the engine's route array, stashing @cfg on the
   route's egress.callback_data so the bootstrap/task entries can reach it. */
int
pm_register_tunnel_route (Portmux *self, void *cfg_, int is_server)
{
    PmTunnelCfg *cfg = cfg_;
    PortmuxRoute *r;

    if (self->route_count >= PM_MAX_ROUTES) {
        free (cfg);
        return -1;
    }
    r = &self->routes[self->route_count];
    memset (r, 0, sizeof *r);
    r->proto = is_server ? PORTMUX_PROTO_TUNNEL_SERVER
                         : PORTMUX_PROTO_TUNNEL_CLIENT;
    r->owner = self;
    r->listen_fd = -1;
    /* Smuggle the tunnel cfg via the egress callback_data slot; mark valid so
       the struct travels with the route. The egress kind is CALLBACK but the
       engine never invokes it for tunnel protos. */
    r->egress.kind = PORTMUX_EGRESS_CALLBACK;
    r->egress.callback = NULL;
    r->egress.callback_data = cfg;
    r->egress_valid = 1;
    self->route_count++;
    return 0;
}

int
portmux_add_tunnel_client (Portmux *self,
                           const char *listen_addr, int listen_port,
                           const char *server_addr, int server_port,
                           const char *target_addr, int target_port,
                           const unsigned char psk[PM_TUNNEL_PSK_LEN],
                           PmTunnelCipher cipher,
                           const PortmuxEgress *egress)
{
    (void)listen_addr; (void)listen_port; /* v1 client has no local listener */
    if (!self || noise_init () != NOISE_ERROR_NONE)
        return -1;
    PmTunnelCfg *cfg = alloc_cfg (self);
    if (!cfg)
        return -1;
    cfg->is_server = 0;
    snprintf (cfg->server_addr, sizeof cfg->server_addr, "%s", server_addr);
    cfg->server_port = server_port;
    snprintf (cfg->target_addr, sizeof cfg->target_addr, "%s",
              target_addr ? target_addr : "127.0.0.1");
    cfg->target_port = target_port;
    memcpy (cfg->psk, psk, PM_TUNNEL_PSK_LEN);
    cfg->cipher = cipher;
    if (egress) { cfg->egress = *egress; cfg->egress_valid = 1; }
    return pm_register_tunnel_route (self, cfg, 0);
}

int
portmux_add_tunnel_server (Portmux *self,
                           const char *listen_addr, int listen_port,
                           const char *bridge_addr, int bridge_port,
                           const unsigned char psk[PM_TUNNEL_PSK_LEN],
                           PmTunnelCipher cipher)
{
    if (!self || noise_init () != NOISE_ERROR_NONE)
        return -1;
    PmTunnelCfg *cfg = alloc_cfg (self);
    if (!cfg)
        return -1;
    cfg->is_server = 1;
    snprintf (cfg->server_addr, sizeof cfg->server_addr, "%s",
              listen_addr ? listen_addr : "0.0.0.0");
    cfg->server_port = listen_port;
    snprintf (cfg->bridge_addr, sizeof cfg->bridge_addr, "%s",
              bridge_addr ? bridge_addr : "127.0.0.1");
    cfg->bridge_port = bridge_port;
    memcpy (cfg->psk, psk, PM_TUNNEL_PSK_LEN);
    cfg->cipher = cipher;
    return pm_register_tunnel_route (self, cfg, 1);
}
