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

/* ───────────────────────── cooperative byte I/O ─────────────────────────
 * read_full / write_full mirror portmux-socks.c: loop over the hev-task
 * non-blocking socket calls honoring shutdown (-2) and EAGAIN.
 */
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

/* ───────────────────────── encrypted relay ─────────────────────────
 * One task, both fds. Mirrors hev_task_io_splice's discipline exactly: each
 * iteration tries BOTH directions with non-blocking I/O (the fds are driven by
 * hev-task's reactor), and yields HEV_TASK_WAITIO only when BOTH directions
 * would block (so the scheduler waits on either fd), or HEV_TASK_YIELD when
 * progress was made. The only difference from a raw splice is the AEAD seal
 * (plain->noise) and open (noise->plain) and the u16 length framing.
 *
 * Per-direction state machine avoids partial-frame and partial-write hazards:
 *   up:  read plaintext -> seal -> frame -> drain-write to noise_fd
 *   dn:  read+reassemble a frame from noise_fd -> open -> drain-write to plain_fd
 * res convention (like task_io_splice): 1 = made progress, 0 = would block,
 * -1 = closed/error (direction done).
 */

typedef struct
{
    /* pending output bytes not yet fully written */
    unsigned char *out;           /* heap PM_TUNNEL_MAX_NOISE_MSG */
    size_t out_len, out_sent;
    /* inbound frame reassembly (dn only) */
    unsigned char hdr[2];
    size_t hdr_got;
    unsigned char *body;          /* heap PM_TUNNEL_MAX_NOISE_MSG */
    size_t body_len, body_got;
    int have_hdr;
} RelayDir;

/* plain -> noise: read plaintext, AEAD seal, frame, write. */
static int
dir_up (RelayDir *d, int plain_fd, int noise_fd, NoiseCipherState *tx,
        unsigned char *scratch)
{
    int res = 0;

    /* flush any pending framed output first */
    if (d->out_len > d->out_sent) {
        ssize_t s = send (noise_fd, d->out + d->out_sent,
                          d->out_len - d->out_sent, MSG_DONTWAIT);
        if (s > 0) { d->out_sent += (size_t)s; res = 1; }
        else if (s < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return -1;
        if (d->out_len > d->out_sent) return res; /* still more to flush */
        d->out_len = d->out_sent = 0;
    }

    /* read a new chunk of plaintext and seal it */
    ssize_t n = recv (plain_fd, scratch, PM_TUNNEL_MAX_PLAINTEXT, MSG_DONTWAIT);
    if (n == 0) return -1;
    if (n < 0) return (errno == EAGAIN || errno == EWOULDBLOCK) ? res : -1;

    NoiseBuffer mb;
    /* frame layout: [2 len][ciphertext]; seal into d->out+2 */
    memcpy (d->out + 2, scratch, (size_t)n);
    noise_buffer_set_inout (mb, d->out + 2, (size_t)n, PM_TUNNEL_MAX_NOISE_MSG - 2);
    if (noise_cipherstate_encrypt (tx, &mb) != NOISE_ERROR_NONE) return -1;
    d->out[0] = (unsigned char)((mb.size >> 8) & 0xff);
    d->out[1] = (unsigned char)(mb.size & 0xff);
    d->out_len = mb.size + 2;
    d->out_sent = 0;
    /* try to write immediately */
    ssize_t s = send (noise_fd, d->out, d->out_len, MSG_DONTWAIT);
    if (s > 0) d->out_sent = (size_t)s;
    else if (s < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return -1;
    if (d->out_len > d->out_sent) return 1; /* progress; more to flush later */
    d->out_len = d->out_sent = 0;
    return 1;
}

/* noise -> plain: reassemble a frame, AEAD open, write plaintext. */
static int
dir_dn (RelayDir *d, int noise_fd, int plain_fd, NoiseCipherState *rx)
{
    int res = 0;

    /* flush pending plaintext output first */
    if (d->out_len > d->out_sent) {
        ssize_t s = send (plain_fd, d->out + d->out_sent,
                          d->out_len - d->out_sent, MSG_DONTWAIT);
        if (s > 0) { d->out_sent += (size_t)s; res = 1; }
        else if (s < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return -1;
        if (d->out_len > d->out_sent) return res;
        d->out_len = d->out_sent = 0;
    }

    /* reassemble header */
    while (d->hdr_got < 2) {
        ssize_t r = recv (noise_fd, d->hdr + d->hdr_got, 2 - d->hdr_got, MSG_DONTWAIT);
        if (r == 0) return -1;
        if (r < 0) return (errno == EAGAIN || errno == EWOULDBLOCK) ? res : -1;
        d->hdr_got += (size_t)r; res = 1;
        if (d->hdr_got == 2) {
            d->body_len = ((size_t)d->hdr[0] << 8) | d->hdr[1];
            d->body_got = 0;
            if (d->body_len == 0 || d->body_len > PM_TUNNEL_MAX_NOISE_MSG) return -1;
        }
    }
    /* reassemble body */
    while (d->body_got < d->body_len) {
        ssize_t r = recv (noise_fd, d->body + d->body_got,
                          d->body_len - d->body_got, MSG_DONTWAIT);
        if (r == 0) return -1;
        if (r < 0) return (errno == EAGAIN || errno == EWOULDBLOCK) ? res : -1;
        d->body_got += (size_t)r; res = 1;
    }

    /* full frame: open it */
    NoiseBuffer mb;
    noise_buffer_set_inout (mb, d->body, d->body_len, PM_TUNNEL_MAX_NOISE_MSG);
    d->hdr_got = 0; /* consume */
    if (noise_cipherstate_decrypt (rx, &mb) != NOISE_ERROR_NONE) return -1;
    memcpy (d->out, mb.data, mb.size);
    d->out_len = mb.size; d->out_sent = 0;
    ssize_t s = send (plain_fd, d->out, d->out_len, MSG_DONTWAIT);
    if (s > 0) d->out_sent = (size_t)s;
    else if (s < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return -1;
    return 1;
}

static void
run_relay (Portmux *self, int plain_fd, int noise_fd,
           NoiseCipherState *tx, NoiseCipherState *rx)
{
    RelayDir up = { 0 }, dn = { 0 };
    unsigned char *scratch;
    int res_f = 1, res_b = 1;

    up.out = malloc (PM_TUNNEL_MAX_NOISE_MSG);
    dn.out = malloc (PM_TUNNEL_MAX_NOISE_MSG);
    dn.body = malloc (PM_TUNNEL_MAX_NOISE_MSG);
    scratch = malloc (PM_TUNNEL_MAX_PLAINTEXT);
    if (!up.out || !dn.out || !dn.body || !scratch)
        goto out;

    pm_set_nodelay (plain_fd);
    pm_set_nodelay (noise_fd);
    hev_task_add_fd (hev_task_self (), plain_fd, POLLIN);
    hev_task_add_fd (hev_task_self (), noise_fd, POLLIN);

    for (;;) {
        HevTaskYieldType type;

        if (res_f >= 0)
            res_f = dir_up (&up, plain_fd, noise_fd, tx, scratch);
        if (res_b >= 0)
            res_b = dir_dn (&dn, noise_fd, plain_fd, rx);

        if (res_f > 0 || res_b > 0)
            type = HEV_TASK_YIELD;      /* progress: keep pumping */
        else if ((res_f & res_b) == 0)
            type = HEV_TASK_WAITIO;     /* both blocked: wait on either fd */
        else
            break;                      /* a direction closed */

        hev_task_yield (type);
        if (!self->run)
            break;
    }

    hev_task_del_fd (hev_task_self (), plain_fd);
    hev_task_del_fd (hev_task_self (), noise_fd);
out:
    free (up.out); free (dn.out); free (dn.body); free (scratch);
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
        PM_LOG_I ("tunnel-client: tunnel up to %s:%d", cfg->server_addr,
                  cfg->server_port);

        /* Connect the local plaintext target (e.g. adbd). */
        family = portmux_resolve (cfg->target_addr, cfg->target_port,
                                  SOCK_STREAM, 0, &ss, &sslen);
        if (family < 0)
            goto reconnect;
        tgt_fd = hev_task_io_socket_socket (family, SOCK_STREAM, 0);
        if (tgt_fd < 0)
            goto reconnect;
        hev_task_add_fd (hev_task_self (), tgt_fd, POLLIN | POLLOUT);
        if (hev_task_io_socket_connect (tgt_fd, (struct sockaddr *)&ss, sslen,
                                        pm_run_yielder, self) < 0) {
            PM_LOG_I ("tunnel-client: target %s:%d connect failed",
                      cfg->target_addr, cfg->target_port);
            goto reconnect;
        }

        run_relay (self, tgt_fd, srv_fd, tx, rx);

reconnect:
        if (tx) { noise_cipherstate_free (tx); tx = NULL; }
        if (rx) { noise_cipherstate_free (rx); rx = NULL; }
        if (tgt_fd >= 0) { hev_task_del_fd (hev_task_self (), tgt_fd); close (tgt_fd); tgt_fd = -1; }
        if (srv_fd >= 0) { hev_task_del_fd (hev_task_self (), srv_fd); close (srv_fd); srv_fd = -1; }
        if (!self->run)
            break;
        hev_task_sleep (1000); /* backoff before reconnecting */
    }

    pm_task_unregister (self, &node);
}

/* ───────────────────────── server ─────────────────────────
 * Accept one encrypted client, handshake as responder, then accept one
 * plaintext bridge connection (the laptop's adb) and relay the two. v1 is 1:1
 * (sufficient for a single adb session); multiplexing is a future refinement.
 */
typedef struct
{
    PmTunnelCfg *cfg;
    int client_fd;
    NoiseCipherState *tx;
    NoiseCipherState *rx;
} PmServerSession;

static void
tunnel_server_session_task (void *data)
{
    PmServerSession *s = data;
    PmTunnelCfg *cfg = s->cfg;
    Portmux *self = cfg->owner;
    PmTaskNode node;
    struct sockaddr_storage peer;
    socklen_t plen;
    int bridge_fd = -1;

    pm_task_register (self, &node);

    PM_LOG_I ("tunnel-server: client up; awaiting bridge connection on %s:%d",
              cfg->bridge_addr, cfg->bridge_port);

    /* Accept exactly one laptop connection on the bridge listener. */
    hev_task_add_fd (hev_task_self (), cfg->bridge_fd, POLLIN);
    plen = sizeof (peer);
    bridge_fd = hev_task_io_socket_accept (cfg->bridge_fd,
                                           (struct sockaddr *)&peer, &plen,
                                           pm_run_yielder, self);
    if (bridge_fd < 0) { PM_LOG_W ("tunnel-server: bridge accept failed"); goto done; }
    PM_LOG_I ("tunnel-server: bridge connection accepted");
    /* Stop listening on the bridge-listener fd from this task; run_relay will
       register the accepted bridge_fd + client_fd it uses. */
    hev_task_del_fd (hev_task_self (), cfg->bridge_fd);

    run_relay (self, bridge_fd, s->client_fd, s->tx, s->rx);

done:
    if (s->tx) noise_cipherstate_free (s->tx);
    if (s->rx) noise_cipherstate_free (s->rx);
    if (bridge_fd >= 0) { hev_task_del_fd (hev_task_self (), bridge_fd); close (bridge_fd); }
    hev_task_del_fd (hev_task_self (), s->client_fd);
    close (s->client_fd);
    free (s);
    pm_task_unregister (self, &node);
}

static void
tunnel_server_task (void *data)
{
    PortmuxRoute *route = data;
    PmTunnelCfg *cfg = (PmTunnelCfg *)route->egress.callback_data;
    Portmux *self = cfg->owner;
    PmTaskNode node;

    pm_task_register (self, &node);
    hev_task_add_fd (hev_task_self (), cfg->listen_fd, POLLIN);
    PM_LOG_I ("tunnel-server: listening for clients on %s:%d, bridge %s:%d",
              cfg->server_addr, cfg->server_port, cfg->bridge_addr,
              cfg->bridge_port);

    while (self->run) {
        struct sockaddr_storage peer;
        socklen_t plen = sizeof (peer);
        int cfd = hev_task_io_socket_accept (cfg->listen_fd,
                                             (struct sockaddr *)&peer, &plen,
                                             pm_run_yielder, self);
        if (cfd == -2)
            break;
        if (cfd < 0)
            continue;
        hev_task_add_fd (hev_task_self (), cfd, POLLIN | POLLOUT);
        pm_set_nodelay (cfd);

        NoiseCipherState *tx = NULL, *rx = NULL;
        if (do_handshake (self, cfd, NOISE_ROLE_RESPONDER, cfg->psk,
                          cfg->cipher, &tx, &rx) < 0) {
            PM_LOG_W ("tunnel-server: client handshake rejected (bad PSK?)");
            hev_task_del_fd (hev_task_self (), cfd);
            close (cfd);
            continue;
        }
        PmServerSession *s = calloc (1, sizeof *s);
        if (!s) { close (cfd); continue; }
        s->cfg = cfg; s->client_fd = cfd; s->tx = tx; s->rx = rx;
        HevTask *t = hev_task_new (-1);
        if (!t) { noise_cipherstate_free (tx); noise_cipherstate_free (rx); close (cfd); free (s); continue; }
        /* Transfer fd ownership: cfd was registered to THIS task for the
           handshake; the session task will re-add it. An fd is bound to one
           task's reactor slot, so it MUST be removed here or the session's
           WAITIO never wakes on it. */
        hev_task_del_fd (hev_task_self (), cfd);
        hev_task_run (t, tunnel_server_session_task, s);
    }

    hev_task_del_fd (hev_task_self (), cfg->listen_fd);
    close (cfg->listen_fd);
    if (cfg->bridge_fd >= 0) { close (cfg->bridge_fd); cfg->bridge_fd = -1; }
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

    /* bridge (laptop-facing) listener */
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
