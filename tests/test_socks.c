/*
 ============================================================================
 Name        : test_socks.c
 Description : End-to-end SOCKS5 test for portmux (loopback).
 *
 *   socks client --> portmux SOCKS5 :SPORT --> echo target :TPORT
 *
 * Exercises RFC 1928 no-auth, CONNECT (TCP) and UDP ASSOCIATE through the
 * in-process engine against a plain blocking echo server. Asserts the echoed
 * payloads match.
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "portmux.h"

#define TCP_TARGET_PORT 48901
#define UDP_TARGET_PORT 48902
#define SOCKS_PORT      48911

static volatile int echo_run = 1;

/* ── echo targets (TCP + UDP) ── */
static void *
echo_thread (void *arg)
{
    (void)arg;
    int tcp_fd = socket (AF_INET, SOCK_STREAM, 0);
    int udp_fd = socket (AF_INET, SOCK_DGRAM, 0);
    int on = 1;
    setsockopt (tcp_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on));
    setsockopt (udp_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on));

    struct sockaddr_in a = { 0 };
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

    a.sin_port = htons (TCP_TARGET_PORT);
    if (bind (tcp_fd, (struct sockaddr *)&a, sizeof (a)) < 0) { perror ("tcp bind"); exit (2); }
    listen (tcp_fd, 8);

    a.sin_port = htons (UDP_TARGET_PORT);
    if (bind (udp_fd, (struct sockaddr *)&a, sizeof (a)) < 0) { perror ("udp bind"); exit (2); }

    fd_set rfds;
    while (echo_run) {
        FD_ZERO (&rfds);
        FD_SET (tcp_fd, &rfds);
        FD_SET (udp_fd, &rfds);
        int mx = tcp_fd > udp_fd ? tcp_fd : udp_fd;
        struct timeval tv = { 0, 200 * 1000 };
        int r = select (mx + 1, &rfds, NULL, NULL, &tv);
        if (r <= 0)
            continue;
        if (FD_ISSET (tcp_fd, &rfds)) {
            int c = accept (tcp_fd, NULL, NULL);
            if (c >= 0) {
                char buf[4096];
                ssize_t n;
                while ((n = recv (c, buf, sizeof (buf), 0)) > 0)
                    if (send (c, buf, n, 0) < 0) break;
                close (c);
            }
        }
        if (FD_ISSET (udp_fd, &rfds)) {
            char buf[4096];
            struct sockaddr_in from;
            socklen_t fl = sizeof (from);
            ssize_t n = recvfrom (udp_fd, buf, sizeof (buf), 0,
                                  (struct sockaddr *)&from, &fl);
            if (n > 0)
                sendto (udp_fd, buf, n, 0, (struct sockaddr *)&from, fl);
        }
    }
    close (tcp_fd);
    close (udp_fd);
    return NULL;
}

/* ── portmux runner ── */
static Portmux *g_pm;
static void *
pm_thread (void *arg)
{
    (void)arg;
    portmux_run (g_pm);
    return NULL;
}

static int
dial_socks (void)
{
    int fd = socket (AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { 0 };
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    a.sin_port = htons (SOCKS_PORT);
    struct timeval tv = { 3, 0 };
    setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv));
    if (connect (fd, (struct sockaddr *)&a, sizeof (a)) < 0) {
        perror ("socks connect");
        close (fd);
        return -1;
    }
    return fd;
}

/* Perform the no-auth greeting. Returns 0 on success. */
static int
socks_greet (int fd)
{
    unsigned char greet[3] = { 0x05, 0x01, 0x00 }; /* VER, 1 method, NOAUTH */
    unsigned char resp[2];
    if (send (fd, greet, sizeof (greet), 0) != 3)
        return -1;
    if (recv (fd, resp, 2, 0) != 2)
        return -1;
    if (resp[0] != 0x05 || resp[1] != 0x00) {
        fprintf (stderr, "greet rejected: %02x %02x\n", resp[0], resp[1]);
        return -1;
    }
    return 0;
}

/* Read a full SOCKS5 reply (VER REP RSV ATYP ADDR PORT). Returns 0 on OK. */
static int
read_reply (int fd)
{
    unsigned char hdr[4];
    if (recv (fd, hdr, 4, 0) != 4)
        return -1;
    if (hdr[0] != 0x05 || hdr[1] != 0x00) {
        fprintf (stderr, "reply failed rep=%02x\n", hdr[1]);
        return -1;
    }
    int addrlen = (hdr[3] == 0x01) ? 4 : (hdr[3] == 0x04) ? 16 : -1;
    if (addrlen < 0)
        return -1;
    unsigned char rest[18];
    if (recv (fd, rest, addrlen + 2, 0) != addrlen + 2)
        return -1;
    return 0;
}

static int
test_connect (void)
{
    int fd = dial_socks ();
    if (fd < 0)
        return -1;
    if (socks_greet (fd) < 0) { close (fd); return -1; }

    /* CONNECT 127.0.0.1:TCP_TARGET_PORT (ATYP IPv4) */
    unsigned char req[10] = { 0x05, 0x01, 0x00, 0x01,
                              127, 0, 0, 1,
                              (TCP_TARGET_PORT >> 8) & 0xff,
                              TCP_TARGET_PORT & 0xff };
    if (send (fd, req, sizeof (req), 0) != 10) { close (fd); return -1; }
    if (read_reply (fd) < 0) { close (fd); return -1; }

    const char *msg = "hello-socks-connect";
    char buf[256] = { 0 };
    send (fd, msg, strlen (msg), 0);
    ssize_t n = recv (fd, buf, sizeof (buf), 0);
    close (fd);
    if (n != (ssize_t)strlen (msg) || memcmp (buf, msg, n) != 0) {
        fprintf (stderr, "CONNECT FAIL: got %zd bytes '%.*s'\n",
                 n, (int)(n > 0 ? n : 0), buf);
        return -1;
    }
    printf ("SOCKS CONNECT OK: echoed %zd bytes\n", n);
    return 0;
}

static int
test_udp_associate (void)
{
    int ctrl = dial_socks ();
    if (ctrl < 0)
        return -1;
    if (socks_greet (ctrl) < 0) { close (ctrl); return -1; }

    /* UDP ASSOCIATE; client addr 0.0.0.0:0 (we don't know our src port yet) */
    unsigned char req[10] = { 0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
    if (send (ctrl, req, sizeof (req), 0) != 10) { close (ctrl); return -1; }

    /* Read reply: VER REP RSV ATYP BND.ADDR BND.PORT */
    unsigned char hdr[4];
    if (recv (ctrl, hdr, 4, 0) != 4) { close (ctrl); return -1; }
    if (hdr[0] != 0x05 || hdr[1] != 0x00 || hdr[3] != 0x01) {
        fprintf (stderr, "UDP ASSOCIATE reply bad rep=%02x atyp=%02x\n",
                 hdr[1], hdr[3]);
        close (ctrl);
        return -1;
    }
    unsigned char bnd[6];
    if (recv (ctrl, bnd, 6, 0) != 6) { close (ctrl); return -1; }
    int relay_port = (bnd[4] << 8) | bnd[5];

    /* The relay binds on the listen address (127.0.0.1). Send a UDP datagram
       wrapped in the SOCKS5 UDP header targeting the echo server. */
    int ufd = socket (AF_INET, SOCK_DGRAM, 0);
    struct timeval tv = { 3, 0 };
    setsockopt (ufd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv));
    struct sockaddr_in relay = { 0 };
    relay.sin_family = AF_INET;
    relay.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    relay.sin_port = htons (relay_port);

    const char *msg = "hello-socks-udp";
    unsigned char pkt[256];
    size_t off = 0;
    pkt[off++] = 0; pkt[off++] = 0;  /* RSV */
    pkt[off++] = 0;                  /* FRAG */
    pkt[off++] = 0x01;               /* ATYP IPv4 */
    pkt[off++] = 127; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 1;
    pkt[off++] = (UDP_TARGET_PORT >> 8) & 0xff;
    pkt[off++] = UDP_TARGET_PORT & 0xff;
    memcpy (pkt + off, msg, strlen (msg));
    off += strlen (msg);

    if (sendto (ufd, pkt, off, 0, (struct sockaddr *)&relay,
                sizeof (relay)) < 0) {
        perror ("udp sendto relay");
        close (ufd); close (ctrl);
        return -1;
    }

    unsigned char rbuf[512];
    ssize_t rn = recv (ufd, rbuf, sizeof (rbuf), 0);
    close (ufd);
    close (ctrl);
    if (rn <= 0) {
        fprintf (stderr, "UDP ASSOCIATE FAIL: no reply (%zd)\n", rn);
        return -1;
    }
    /* reply has a 10-byte IPv4 SOCKS UDP header before the echoed payload */
    if (rn < 10 + (ssize_t)strlen (msg)
        || memcmp (rbuf + 10, msg, strlen (msg)) != 0) {
        fprintf (stderr, "UDP ASSOCIATE FAIL: bad reply (%zd bytes)\n", rn);
        return -1;
    }
    printf ("SOCKS UDP ASSOCIATE OK: echoed %zu bytes\n", strlen (msg));
    return 0;
}

int
main (void)
{
    pthread_t echo_tid, pm_tid;
    int failures = 0;

    pthread_create (&echo_tid, NULL, echo_thread, NULL);
    usleep (200 * 1000);

    g_pm = portmux_new ();
    if (!g_pm) { fprintf (stderr, "portmux_new failed\n"); return 1; }

    if (portmux_add_socks (g_pm, "127.0.0.1", SOCKS_PORT, NULL) < 0) {
        fprintf (stderr, "portmux_add_socks failed\n");
        return 1;
    }

    pthread_create (&pm_tid, NULL, pm_thread, NULL);
    usleep (300 * 1000); /* let the listener come up */

    fprintf (stderr, "-> test_connect\n");
    failures += test_connect () < 0;
    fprintf (stderr, "-> test_connect #2 (accept loop keeps serving)\n");
    failures += test_connect () < 0;
    fprintf (stderr, "-> test_udp_associate\n");
    failures += test_udp_associate () < 0;
    fprintf (stderr, "-> stopping\n");

    portmux_stop (g_pm);
    pthread_join (pm_tid, NULL);
    portmux_destroy (g_pm);

    echo_run = 0;
    pthread_join (echo_tid, NULL);

    if (failures) {
        printf ("RESULT: %d failure(s)\n", failures);
        return 1;
    }
    printf ("RESULT: all passed\n");
    return 0;
}
