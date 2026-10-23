/*
 ============================================================================
 Name        : portmux-socks.c
 Description : SOCKS5 inbound for portmux. Implements RFC 1928 no-auth,
               CONNECT (TCP) and UDP ASSOCIATE, reusing portmux's egress
               machinery so every upstream socket the proxy opens is pinned
               per the route's PortmuxEgress (per-connection egress pinning,
               no root). Built on the same hev-task cooperative scheduler.
 License     : MIT
 ============================================================================
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>
#include <hev-task-system.h>

#include "portmux.h"
#include "portmux-log.h"
#include "portmux-addr.h"
#include "portmux-internal.h"

/* SOCKS5 constants (RFC 1928). */
#define S5_VER 0x05
#define S5_METHOD_NOAUTH 0x00
#define S5_METHOD_REJECT 0xFF
#define S5_CMD_CONNECT 0x01
#define S5_CMD_BIND 0x02
#define S5_CMD_UDP_ASSOCIATE 0x03
#define S5_ATYP_IPV4 0x01
#define S5_ATYP_DOMAIN 0x03
#define S5_ATYP_IPV6 0x04
/* reply codes */
#define S5_REP_OK 0x00
#define S5_REP_GENERAL 0x01
#define S5_REP_NOT_ALLOWED 0x02
#define S5_REP_HOST_UNREACH 0x04
#define S5_REP_CONN_REFUSED 0x05
#define S5_REP_CMD_UNSUP 0x07
#define S5_REP_ATYP_UNSUP 0x08

#define S5_UDP_DGRAM_MAX 65536
#ifndef S5_UDP_IDLE_MS
#define S5_UDP_IDLE_MS PM_UDP_IDLE_MS
#endif

typedef struct
{
    Portmux *owner;
    PortmuxRoute *route;
    int client_fd;
} PmSocksConn;

/* Read exactly n bytes (cooperatively), honoring shutdown. Returns 0 on
   success, < 0 on error/eof/stop. */
static int
read_full (Portmux *self, int fd, void *buf, size_t n)
{
    size_t got = 0;
    unsigned char *p = buf;
    while (got < n) {
        ssize_t r = hev_task_io_socket_recv (fd, p + got, n - got, 0,
                                             pm_run_yielder, self);
        if (r == -2)
            return -1; /* shutdown */
        if (r == 0)
            return -1; /* eof */
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            return -1;
        }
        got += (size_t)r;
    }
    return 0;
}

/* Write exactly n bytes (cooperatively). Returns 0 on success, < 0 on error. */
static int
write_full (Portmux *self, int fd, const void *buf, size_t n)
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

/* Build a SOCKS5 reply into buf. bnd is the bound address to report (may be
   all-zero). Returns the reply length. */
static size_t
build_reply (unsigned char *buf, unsigned char rep,
             const struct sockaddr_storage *bnd)
{
    buf[0] = S5_VER;
    buf[1] = rep;
    buf[2] = 0x00; /* RSV */

    if (bnd && bnd->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)bnd;
        buf[3] = S5_ATYP_IPV6;
        memcpy (buf + 4, &s6->sin6_addr, 16);
        memcpy (buf + 20, &s6->sin6_port, 2);
        return 22;
    } else if (bnd && bnd->ss_family == AF_INET) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)bnd;
        buf[3] = S5_ATYP_IPV4;
        memcpy (buf + 4, &s4->sin_addr, 4);
        memcpy (buf + 8, &s4->sin_port, 2);
        return 10;
    }
    /* unknown/none: report 0.0.0.0:0 */
    buf[3] = S5_ATYP_IPV4;
    memset (buf + 4, 0, 6);
    return 10;
}

static int
send_reply (Portmux *self, int fd, unsigned char rep,
            const struct sockaddr_storage *bnd)
{
    unsigned char buf[22];
    size_t n = build_reply (buf, rep, bnd);
    return write_full (self, fd, buf, n);
}

/* Parse a SOCKS5 address (ATYP + ADDR + PORT) from a freshly-read request on
   the control socket. Fills host (numeric or domain string) and port. Returns
   0 on success, < 0 on error. atyp_out receives the ATYP. */
static int
read_socks_addr (Portmux *self, int fd, char *host, size_t hostsz, int *port,
                 int *atyp_out)
{
    unsigned char atyp;
    if (read_full (self, fd, &atyp, 1) < 0)
        return -1;
    *atyp_out = atyp;

    if (atyp == S5_ATYP_IPV4) {
        unsigned char a[4];
        if (read_full (self, fd, a, 4) < 0)
            return -1;
        if (!inet_ntop (AF_INET, a, host, hostsz))
            return -1;
    } else if (atyp == S5_ATYP_IPV6) {
        unsigned char a[16];
        if (read_full (self, fd, a, 16) < 0)
            return -1;
        if (!inet_ntop (AF_INET6, a, host, hostsz))
            return -1;
    } else if (atyp == S5_ATYP_DOMAIN) {
        unsigned char len;
        if (read_full (self, fd, &len, 1) < 0)
            return -1;
        if ((size_t)len + 1 > hostsz)
            return -1;
        if (read_full (self, fd, host, len) < 0)
            return -1;
        host[len] = '\0';
    } else {
        return -1;
    }

    unsigned char pb[2];
    if (read_full (self, fd, pb, 2) < 0)
        return -1;
    *port = (pb[0] << 8) | pb[1];
    return 0;
}

/* ───────────────── SOCKS5 CONNECT (TCP) ───────────────── */

static int
socks_do_connect (PmSocksConn *c, const char *host, int port)
{
    Portmux *self = c->owner;
    PortmuxRoute *r = c->route;
    struct sockaddr_storage ss, bnd;
    socklen_t sslen, bndlen = sizeof (bnd);
    int family, up_fd, res;

    family = portmux_resolve (host, port, SOCK_STREAM, 0, &ss, &sslen);
    if (family < 0) {
        send_reply (self, c->client_fd, S5_REP_HOST_UNREACH, NULL);
        return -1;
    }

    up_fd = pm_make_upstream_fd (r, family, SOCK_STREAM);
    if (up_fd < 0) {
        send_reply (self, c->client_fd, S5_REP_GENERAL, NULL);
        return -1;
    }

    hev_task_add_fd (hev_task_self (), up_fd, POLLIN | POLLOUT);
    res = hev_task_io_socket_connect (up_fd, (struct sockaddr *)&ss, sslen,
                                      pm_run_yielder, self);
    if (res < 0) {
        PM_LOG_I ("socks: connect %s:%d failed", host, port);
        send_reply (self, c->client_fd, S5_REP_CONN_REFUSED, NULL);
        hev_task_del_fd (hev_task_self (), up_fd);
        close (up_fd);
        return -1;
    }

    /* Report the bound local address of the upstream socket. */
    memset (&bnd, 0, sizeof (bnd));
    if (getsockname (up_fd, (struct sockaddr *)&bnd, &bndlen) < 0)
        bndlen = 0;
    if (send_reply (self, c->client_fd, S5_REP_OK,
                    bndlen ? &bnd : NULL) < 0) {
        hev_task_del_fd (hev_task_self (), up_fd);
        close (up_fd);
        return -1;
    }

    PM_LOG_D ("socks: CONNECT %d <-> %s:%d established", c->client_fd, host,
              port);

    pm_set_nodelay (up_fd);
    pm_set_nodelay (c->client_fd);
    hev_task_add_fd (hev_task_self (), c->client_fd, POLLIN | POLLOUT);

    hev_task_io_splice (c->client_fd, c->client_fd, up_fd, up_fd,
                        PM_TCP_SPLICE_BUF, pm_run_yielder, self);

    hev_task_del_fd (hev_task_self (), up_fd);
    close (up_fd);
    return 0;
}

/* ───────────────── SOCKS5 UDP ASSOCIATE ───────────────── */
/*
 * The client opens a TCP control connection and issues UDP ASSOCIATE. We bind
 * a UDP relay socket on the proxy's listen address, report its ip:port, and
 * relay datagrams:
 *   client -> relay: [RSV(2) FRAG(1) ATYP ADDR PORT DATA] -> strip header,
 *                    forward DATA to ADDR:PORT via an egress-pinned upstream.
 *   target -> relay -> client: wrap DATA in the same header and sendto the
 *                    client's observed UDP source address.
 * The association lives as long as the TCP control connection is open (we poll
 * both the control fd and the relay fd; control EOF tears it down). One upstream
 * socket is kept per distinct destination (simple single-dest fast path plus a
 * small table), each created through pm_make_upstream_fd so egress pinning
 * applies per association.
 */

typedef struct S5UdpDst S5UdpDst;
struct S5UdpDst
{
    S5UdpDst *next;
    struct sockaddr_storage dst; /* resolved target */
    socklen_t dstlen;
    int up_fd;                   /* connected to dst, egress-applied */
    unsigned long last_ms;
};

typedef struct
{
    Portmux *owner;
    PortmuxRoute *route;
    int relay_fd;                     /* UDP socket facing the client */
    int have_client;                  /* learned the client's UDP src yet? */
    struct sockaddr_storage client;   /* client's UDP source address */
    socklen_t client_len;
    S5UdpDst *dsts;
} S5UdpAssoc;

static S5UdpDst *
udp_find_dst (S5UdpAssoc *a, const struct sockaddr_storage *d, socklen_t dl)
{
    S5UdpDst *x;
    for (x = a->dsts; x; x = x->next)
        if (x->dstlen == dl && memcmp (&x->dst, d, dl) == 0)
            return x;
    return NULL;
}

static S5UdpDst *
udp_new_dst (S5UdpAssoc *a, const struct sockaddr_storage *d, socklen_t dl,
             int family)
{
    S5UdpDst *x = calloc (1, sizeof (S5UdpDst));
    if (!x)
        return NULL;
    int up_fd = pm_make_upstream_fd (a->route, family, SOCK_DGRAM);
    if (up_fd < 0) {
        free (x);
        return NULL;
    }
    if (connect (up_fd, (struct sockaddr *)d, dl) < 0) {
        close (up_fd);
        free (x);
        return NULL;
    }
    hev_task_add_fd (hev_task_self (), up_fd, POLLIN);
    memcpy (&x->dst, d, dl);
    x->dstlen = dl;
    x->up_fd = up_fd;
    x->last_ms = pm_mono_ms ();
    x->next = a->dsts;
    a->dsts = x;
    return x;
}

/* Build the SOCKS5 UDP reply header (RSV FRAG ATYP ADDR PORT) for datagrams
   returned to the client. Returns header length. */
static size_t
udp_build_hdr (unsigned char *buf, const struct sockaddr_storage *src)
{
    buf[0] = 0; buf[1] = 0; /* RSV */
    buf[2] = 0;             /* FRAG */
    if (src->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)src;
        buf[3] = S5_ATYP_IPV6;
        memcpy (buf + 4, &s6->sin6_addr, 16);
        memcpy (buf + 20, &s6->sin6_port, 2);
        return 22;
    }
    const struct sockaddr_in *s4 = (const struct sockaddr_in *)src;
    buf[3] = S5_ATYP_IPV4;
    memcpy (buf + 4, &s4->sin_addr, 4);
    memcpy (buf + 8, &s4->sin_port, 2);
    return 10;
}

/* Parse the client's SOCKS5 UDP request header. On success sets data/datalen
   to the payload and fills dst host/port. Returns header length (>0) or -1. */
static int
udp_parse_hdr (unsigned char *buf, ssize_t n, char *host, size_t hostsz,
               int *port, unsigned char **data, size_t *datalen)
{
    if (n < 4)
        return -1;
    if (buf[2] != 0)      /* fragmentation not supported */
        return -1;
    unsigned char atyp = buf[3];
    size_t off = 4;
    if (atyp == S5_ATYP_IPV4) {
        if (n < (ssize_t)(off + 4 + 2))
            return -1;
        if (!inet_ntop (AF_INET, buf + off, host, hostsz))
            return -1;
        off += 4;
    } else if (atyp == S5_ATYP_IPV6) {
        if (n < (ssize_t)(off + 16 + 2))
            return -1;
        if (!inet_ntop (AF_INET6, buf + off, host, hostsz))
            return -1;
        off += 16;
    } else if (atyp == S5_ATYP_DOMAIN) {
        unsigned char len = buf[off++];
        if (n < (ssize_t)(off + len + 2))
            return -1;
        if ((size_t)len + 1 > hostsz)
            return -1;
        memcpy (host, buf + off, len);
        host[len] = '\0';
        off += len;
    } else {
        return -1;
    }
    *port = (buf[off] << 8) | buf[off + 1];
    off += 2;
    *data = buf + off;
    *datalen = (size_t)n - off;
    return (int)off;
}

static void
socks_do_udp_associate (PmSocksConn *c)
{
    Portmux *self = c->owner;
    PortmuxRoute *r = c->route;
    struct sockaddr_storage bnd;
    socklen_t bndlen;
    S5UdpAssoc a = { 0 };
    int family, relay_fd;
    unsigned char *cbuf = NULL, *ubuf = NULL;

    /* Bind the UDP relay socket on the proxy's listen address, ephemeral port.
       Resolve family from the listen address. */
    {
        struct sockaddr_storage ls;
        socklen_t lslen;
        family = portmux_resolve (r->listen_addr, 0, SOCK_DGRAM, 1, &ls, &lslen);
        if (family < 0) {
            send_reply (self, c->client_fd, S5_REP_GENERAL, NULL);
            return;
        }
        relay_fd = hev_task_io_socket_socket (family, SOCK_DGRAM, 0);
        if (relay_fd < 0) {
            send_reply (self, c->client_fd, S5_REP_GENERAL, NULL);
            return;
        }
        if (bind (relay_fd, (struct sockaddr *)&ls, lslen) < 0) {
            PM_LOG_W ("socks: udp relay bind: %s", strerror (errno));
            send_reply (self, c->client_fd, S5_REP_GENERAL, NULL);
            close (relay_fd);
            return;
        }
    }

    a.owner = self;
    a.route = r;
    a.relay_fd = relay_fd;
    a.have_client = 0;

    bndlen = sizeof (bnd);
    memset (&bnd, 0, sizeof (bnd));
    if (getsockname (relay_fd, (struct sockaddr *)&bnd, &bndlen) < 0)
        bndlen = 0;

    if (send_reply (self, c->client_fd, S5_REP_OK, bndlen ? &bnd : NULL) < 0) {
        close (relay_fd);
        return;
    }

    cbuf = malloc (S5_UDP_DGRAM_MAX);
    ubuf = malloc (S5_UDP_DGRAM_MAX);
    if (!cbuf || !ubuf)
        goto cleanup;

    PM_LOG_D ("socks: UDP ASSOCIATE relay up (ctrl fd=%d)", c->client_fd);

    hev_task_add_fd (hev_task_self (), relay_fd, POLLIN);
    hev_task_add_fd (hev_task_self (), c->client_fd, POLLIN);

    while (self->run) {
        int did_work = 0;

        /* client -> target: drain all pending client datagrams. */
        for (;;) {
            struct sockaddr_storage from;
            socklen_t fl = sizeof (from);
            ssize_t n = recvfrom (relay_fd, cbuf, S5_UDP_DGRAM_MAX,
                                  MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
            if (n <= 0)
                break;
            did_work = 1;
            char host[256];
            int port;
            unsigned char *data;
            size_t datalen;
            if (!a.have_client) {
                memcpy (&a.client, &from, fl);
                a.client_len = fl;
                a.have_client = 1;
            }
            if (udp_parse_hdr (cbuf, n, host, sizeof (host), &port, &data,
                               &datalen) < 0)
                continue;
            struct sockaddr_storage dss;
            socklen_t dlen;
            int df = portmux_resolve (host, port, SOCK_DGRAM, 0, &dss, &dlen);
            if (df < 0)
                continue;
            S5UdpDst *d = udp_find_dst (&a, &dss, dlen);
            if (!d)
                d = udp_new_dst (&a, &dss, dlen, df);
            if (!d)
                continue;
            (void)send (d->up_fd, data, datalen, 0);
            d->last_ms = pm_mono_ms ();
        }

        /* target -> client: drain all pending upstream replies, wrapped in a
           SOCKS5 UDP header describing the source dst. */
        {
            S5UdpDst *d;
            for (d = a.dsts; d; d = d->next) {
                for (;;) {
                    ssize_t m = recv (d->up_fd, ubuf + 262,
                                      S5_UDP_DGRAM_MAX - 262, MSG_DONTWAIT);
                    if (m <= 0)
                        break;
                    did_work = 1;
                    unsigned char hdr[262];
                    size_t hl = udp_build_hdr (hdr, &d->dst);
                    memcpy (ubuf + 262 - hl, hdr, hl);
                    if (a.have_client)
                        sendto (relay_fd, ubuf + 262 - hl, hl + (size_t)m, 0,
                                (struct sockaddr *)&a.client, a.client_len);
                    d->last_ms = pm_mono_ms ();
                }
            }
        }

        /* control-connection close detection. */
        {
            char probe;
            ssize_t pr = recv (c->client_fd, &probe, 1,
                               MSG_DONTWAIT | MSG_PEEK);
            if (pr == 0)
                break; /* client closed control conn -> end association */
        }

        /* Nothing ready: yield for a short slice so other tasks run and we
           re-poll promptly. hev_task_sleep returns early on wakeup/stop. */
        if (!did_work) {
            if (!self->run)
                break;
            hev_task_sleep (2);
        }
    }

cleanup:
    {
        S5UdpDst *d = a.dsts;
        while (d) {
            S5UdpDst *nx = d->next;
            if (d->up_fd >= 0) {
                hev_task_del_fd (hev_task_self (), d->up_fd);
                close (d->up_fd);
            }
            free (d);
            d = nx;
        }
    }
    free (cbuf);
    free (ubuf);
    hev_task_del_fd (hev_task_self (), relay_fd);
    close (relay_fd);
    PM_LOG_D ("socks: UDP ASSOCIATE relay down");
}

/* ───────────────── per-connection task ───────────────── */

static void
socks_conn_task (void *data)
{
    PmSocksConn *c = data;
    Portmux *self = c->owner;
    PmTaskNode node;
    unsigned char hdr[2];
    int i;

    pm_task_register (self, &node);
    hev_task_add_fd (hev_task_self (), c->client_fd, POLLIN | POLLOUT);
    pm_set_nodelay (c->client_fd);

    /* Greeting: VER NMETHODS METHODS... */
    if (read_full (self, c->client_fd, hdr, 2) < 0)
        goto done;
    if (hdr[0] != S5_VER)
        goto done;
    {
        unsigned char nmethods = hdr[1];
        unsigned char methods[255];
        int ok = 0;
        if (nmethods && read_full (self, c->client_fd, methods, nmethods) < 0)
            goto done;
        for (i = 0; i < nmethods; i++)
            if (methods[i] == S5_METHOD_NOAUTH)
                ok = 1;
        unsigned char sel[2] = { S5_VER,
                                 ok ? S5_METHOD_NOAUTH : S5_METHOD_REJECT };
        if (write_full (self, c->client_fd, sel, 2) < 0 || !ok)
            goto done;
    }

    /* Request: VER CMD RSV ATYP ADDR PORT */
    {
        unsigned char req[3];
        char host[256];
        int port, atyp;
        if (read_full (self, c->client_fd, req, 3) < 0)
            goto done;
        if (req[0] != S5_VER)
            goto done;
        if (read_socks_addr (self, c->client_fd, host, sizeof (host), &port,
                             &atyp) < 0) {
            send_reply (self, c->client_fd, S5_REP_ATYP_UNSUP, NULL);
            goto done;
        }

        switch (req[1]) {
        case S5_CMD_CONNECT:
            socks_do_connect (c, host, port);
            break;
        case S5_CMD_UDP_ASSOCIATE:
            socks_do_udp_associate (c);
            break;
        case S5_CMD_BIND:
        default:
            send_reply (self, c->client_fd, S5_REP_CMD_UNSUP, NULL);
            break;
        }
    }

done:
    hev_task_del_fd (hev_task_self (), c->client_fd);
    close (c->client_fd);
    free (c);
    pm_task_unregister (self, &node);
}

/* ───────────────── listener task ───────────────── */

void
pm_socks_listen_task (void *data)
{
    PortmuxRoute *r = data;
    Portmux *self = r->owner;
    PmTaskNode node;

    pm_task_register (self, &node);
    PM_LOG_D ("socks: listen task started fd=%d", r->listen_fd);
    hev_task_add_fd (hev_task_self (), r->listen_fd, POLLIN);

    while (self->run) {
        struct sockaddr_storage peer;
        socklen_t plen = sizeof (peer);
        PmSocksConn *c;
        HevTask *task;
        int cfd;

        cfd = hev_task_io_socket_accept (r->listen_fd, (struct sockaddr *)&peer,
                                         &plen, pm_run_yielder, self);
        if (cfd == -2)
            break;
        if (cfd < 0)
            continue;

        c = calloc (1, sizeof (PmSocksConn));
        if (!c) {
            close (cfd);
            continue;
        }
        c->owner = self;
        c->route = r;
        c->client_fd = cfd;

        task = hev_task_new (-1);
        if (!task) {
            close (cfd);
            free (c);
            continue;
        }
        hev_task_run (task, socks_conn_task, c);
    }

    hev_task_del_fd (hev_task_self (), r->listen_fd);
    close (r->listen_fd);
    pm_task_unregister (self, &node);
}
