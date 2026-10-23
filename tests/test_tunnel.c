/*
 ============================================================================
 Name        : test_tunnel.c
 Description : End-to-end test for the Noise (NoisePSK_NN) rendezvous tunnel.
 *
 * Topology (all on 127.0.0.1), mirroring Scenario B:
 *
 *   client-app (this test)  ->  SERVER bridge :BRIDGE_PORT
 *                                   |  (portmux tunnel server)
 *                                   v  Noise/AES-GCM over :TUN_PORT
 *                                CLIENT (portmux tunnel client)
 *                                   |  plain splice
 *                                   v
 *                                echo target :TARGET_PORT
 *
 * Two portmux instances run in-process on their own threads (each owns a
 * hev-task scheduler): one tunnel SERVER, one tunnel CLIENT sharing a PSK.
 * The test acts as the "laptop": it connects to the server bridge port and
 * asserts that bytes echo back through the full encrypted path.
 *
 * Also asserts that a client with the WRONG PSK cannot establish the tunnel
 * (the bridge connection yields no echo).
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
#include "portmux-tunnel.h"

#define TARGET_PORT 49201   /* echo target the client splices to */
#define TUN_PORT    49211   /* encrypted client<->server port    */
#define BRIDGE_PORT 49221   /* laptop-facing bridge on the server */

static volatile int echo_run = 1;

/* ── TCP echo target ── */
static void *
echo_thread (void *arg)
{
    (void)arg;
    int fd = socket (AF_INET, SOCK_STREAM, 0);
    int on = 1;
    setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    struct sockaddr_in a = { 0 };
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    a.sin_port = htons (TARGET_PORT);
    if (bind (fd, (struct sockaddr *)&a, sizeof a) < 0) { perror ("echo bind"); exit (2); }
    listen (fd, 8);
    while (echo_run) {
        fd_set r; FD_ZERO (&r); FD_SET (fd, &r);
        struct timeval tv = { 0, 200 * 1000 };
        if (select (fd + 1, &r, 0, 0, &tv) <= 0) continue;
        int c = accept (fd, 0, 0);
        if (c < 0) continue;
        char buf[4096]; ssize_t n;
        while ((n = recv (c, buf, sizeof buf, 0)) > 0)
            if (send (c, buf, n, 0) < 0) break;
        close (c);
    }
    close (fd);
    return NULL;
}

static Portmux *g_server, *g_client, *g_client_bad;
static void *run_pm (void *p) { portmux_run ((Portmux *)p); return NULL; }

static int
bridge_roundtrip (const char *msg)
{
    int fd = socket (AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { 0 };
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    a.sin_port = htons (BRIDGE_PORT);
    struct timeval tv = { 5, 0 };
    setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    if (connect (fd, (struct sockaddr *)&a, sizeof a) < 0) { close (fd); return -1; }
    char buf[256] = { 0 };
    if (send (fd, msg, strlen (msg), 0) < 0) { close (fd); return -1; }
    ssize_t n = recv (fd, buf, sizeof buf, 0);
    close (fd);
    if (n != (ssize_t)strlen (msg) || memcmp (buf, msg, n) != 0)
        return -1;
    return 0;
}

static int
bridge_exchange (void)
{
    int fd = socket (AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { 0 };
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    a.sin_port = htons (BRIDGE_PORT);
    struct timeval tv = { 5, 0 };
    setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    if (connect (fd, (struct sockaddr *)&a, sizeof a) < 0) { close (fd); return -1; }
    const char *msgs[2] = { "hello-through-noise-tunnel", "second-message-same-tunnel" };
    for (int i = 0; i < 2; i++) {
        char buf[256] = { 0 };
        size_t L = strlen (msgs[i]);
        if (send (fd, msgs[i], L, 0) < 0) { close (fd); return -1; }
        size_t got = 0;
        while (got < L) {
            ssize_t n = recv (fd, buf + got, sizeof buf - got, 0);
            if (n <= 0) { close (fd); return -1; }
            got += (size_t)n;
        }
        if (got != L || memcmp (buf, msgs[i], L) != 0) { close (fd); return -1; }
    }
    close (fd);
    return 0;
}

int
main (void)
{
    pthread_t echo_tid, srv_tid, cli_tid;
    unsigned char psk[PM_TUNNEL_PSK_LEN], psk_bad[PM_TUNNEL_PSK_LEN];
    int failures = 0;

    memset (psk, 0x5a, sizeof psk);
    memset (psk_bad, 0x11, sizeof psk_bad);

    pthread_create (&echo_tid, NULL, echo_thread, NULL);
    usleep (200 * 1000);

    /* Server: encrypted listener :TUN_PORT, laptop bridge :BRIDGE_PORT. */
    g_server = portmux_new ();
    if (portmux_add_tunnel_server (g_server, "127.0.0.1", TUN_PORT,
                                   "127.0.0.1", BRIDGE_PORT, psk,
                                   PM_TUNNEL_CIPHER_AESGCM) < 0) {
        fprintf (stderr, "add_tunnel_server failed\n"); return 1;
    }
    pthread_create (&srv_tid, NULL, run_pm, g_server);
    usleep (300 * 1000);

    /* Client: dial server :TUN_PORT, splice to echo target :TARGET_PORT. */
    g_client = portmux_new ();
    if (portmux_add_tunnel_client (g_client, NULL, 0,
                                   "127.0.0.1", TUN_PORT,
                                   "127.0.0.1", TARGET_PORT, psk,
                                   PM_TUNNEL_CIPHER_AESGCM, NULL) < 0) {
        fprintf (stderr, "add_tunnel_client failed\n"); return 1;
    }
    pthread_create (&cli_tid, NULL, run_pm, g_client);
    usleep (500 * 1000); /* allow client handshake + session to come up */

    fprintf (stderr, "-> two-message exchange over one bridge connection\n");
    failures += bridge_exchange () < 0;

    if (failures == 0)
        printf ("TUNNEL OK: encrypted round-trips succeeded\n");
    else
        printf ("TUNNEL FAIL: %d round-trip failure(s)\n", failures);

    /* Wrong-PSK: a client with a different PSK must NOT establish a tunnel, so
       the server has no session and a bridge connection cannot echo. Tear down
       the good client first so only the bad one could (but must not) serve. */
    portmux_stop (g_client);
    pthread_join (cli_tid, NULL);
    portmux_destroy (g_client);
    usleep (300 * 1000);

    g_client_bad = portmux_new ();
    portmux_add_tunnel_client (g_client_bad, NULL, 0, "127.0.0.1", TUN_PORT,
                               "127.0.0.1", TARGET_PORT, psk_bad,
                               PM_TUNNEL_CIPHER_AESGCM, NULL);
    pthread_t bad_tid;
    pthread_create (&bad_tid, NULL, run_pm, g_client_bad);
    usleep (500 * 1000);

    fprintf (stderr, "-> wrong-PSK: bridge round-trip MUST fail\n");
    int bad = bridge_roundtrip ("should-not-echo");
    if (bad == 0) {
        printf ("WRONG-PSK FAIL: data echoed despite PSK mismatch!\n");
        failures++;
    } else {
        printf ("WRONG-PSK OK: no tunnel established (as required)\n");
    }

    portmux_stop (g_client_bad); pthread_join (bad_tid, NULL); portmux_destroy (g_client_bad);
    portmux_stop (g_server); pthread_join (srv_tid, NULL); portmux_destroy (g_server);
    echo_run = 0; pthread_join (echo_tid, NULL);

    if (failures) { printf ("RESULT: %d failure(s)\n", failures); return 1; }
    printf ("RESULT: all passed\n");
    return 0;
}
