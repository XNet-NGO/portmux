/*
 ============================================================================
 Name        : test_relay.c
 Description : End-to-end loopback test for portmux.
 *
 * Layout (all on 127.0.0.1):
 *   client --> portmux :LPORT --> echo target :TPORT
 *
 * A background thread runs the echo targets (plain blocking sockets).
 * Another background thread runs portmux. The main thread acts as the
 * client and asserts the echoed payload matches for both TCP and UDP.
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

#define TCP_TARGET_PORT 48801
#define UDP_TARGET_PORT 48802
#define TCP_LISTEN_PORT 48811
#define UDP_LISTEN_PORT 48812

static volatile int echo_run = 1;

/* ── echo targets ── */
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
    if (bind (tcp_fd, (struct sockaddr *)&a, sizeof (a)) < 0) { perror("tcp bind"); exit(2);}
    listen (tcp_fd, 8);

    a.sin_port = htons (UDP_TARGET_PORT);
    if (bind (udp_fd, (struct sockaddr *)&a, sizeof (a)) < 0) { perror("udp bind"); exit(2);}

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

static struct sockaddr_in
loop (int port)
{
    struct sockaddr_in a = { 0 };
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    a.sin_port = htons (port);
    return a;
}

static int
test_tcp (void)
{
    int fd = socket (AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = loop (TCP_LISTEN_PORT);
    struct timeval tv = { 3, 0 };
    setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv));
    if (connect (fd, (struct sockaddr *)&a, sizeof (a)) < 0) {
        perror ("tcp connect");
        close (fd);
        return -1;
    }
    const char *msg = "hello-tcp-through-portmux";
    char buf[256] = { 0 };
    send (fd, msg, strlen (msg), 0);
    ssize_t n = recv (fd, buf, sizeof (buf), 0);
    close (fd);
    if (n != (ssize_t)strlen (msg) || memcmp (buf, msg, n) != 0) {
        fprintf (stderr, "TCP FAIL: got %zd bytes '%.*s'\n", n, (int)(n>0?n:0), buf);
        return -1;
    }
    printf ("TCP  OK: echoed %zd bytes\n", n);
    return 0;
}

static int
test_udp (void)
{
    int fd = socket (AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = loop (UDP_LISTEN_PORT);
    const char *msg = "hello-udp-through-portmux";
    char buf[256] = { 0 };

    struct timeval tv = { 2, 0 };
    setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv));

    sendto (fd, msg, strlen (msg), 0, (struct sockaddr *)&a, sizeof (a));
    ssize_t n = recv (fd, buf, sizeof (buf), 0);
    close (fd);
    if (n != (ssize_t)strlen (msg) || memcmp (buf, msg, n) != 0) {
        fprintf (stderr, "UDP FAIL: got %zd bytes\n", n);
        return -1;
    }
    printf ("UDP  OK: echoed %zd bytes\n", n);
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

    portmux_add_route (g_pm, PORTMUX_PROTO_TCP, "127.0.0.1", TCP_LISTEN_PORT,
                       "127.0.0.1", TCP_TARGET_PORT, NULL);
    portmux_add_route (g_pm, PORTMUX_PROTO_UDP, "127.0.0.1", UDP_LISTEN_PORT,
                       "127.0.0.1", UDP_TARGET_PORT, NULL);

    pthread_create (&pm_tid, NULL, pm_thread, NULL);
    usleep (300 * 1000); /* let listeners come up */

    fprintf (stderr, "-> test_tcp #1\n");
    failures += test_tcp () < 0;
    fprintf (stderr, "-> test_udp\n");
    failures += test_udp () < 0;
    /* second TCP connection to confirm accept loop keeps serving */
    fprintf (stderr, "-> test_tcp #2\n");
    failures += test_tcp () < 0;
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
