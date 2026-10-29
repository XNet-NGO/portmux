/*
 ============================================================================
 Name        : test_jump.c
 Description : End-to-end multi-hop jump routing over the Noise tunnel.
 *
 *   test (laptop) -> EDGE local listener
 *                      | client carrier (Noise)
 *                      v
 *                    peerA  --(dials, Noise)-->  peerB  --plain--> echo target
 *                      \________ 2-hop: peerA connects target directly ________/
 *
 * Two scenarios, all on 127.0.0.1, each portmux instance on its own thread:
 *   - 2 hops: edge -> peerA -> target         (jumps = [A],   target)
 *   - 3 hops: edge -> peerA -> peerB -> target (jumps = [A,B], target)
 *
 * Asserts bytes echo back through the full multi-hop encrypted path.
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

#define TARGET_PORT 49301
#define PEERA_PORT  49311
#define PEERB_PORT  49312
#define EDGE2_PORT  49321   /* edge local listener for the 2-hop test */
#define EDGE3_PORT  49322   /* edge local listener for the 3-hop test */

static volatile int echo_run = 1;

/* Per-connection echo handler. Real adbd serves many concurrent connections;
   handling each accepted socket on its own detached thread models that (and
   avoids serializing two independent chains that share one echo target). */
static void *
echo_conn (void *arg)
{
    int c = *(int *)arg; free (arg);
    char buf[4096]; ssize_t n;
    while ((n = recv (c, buf, sizeof buf, 0)) > 0)
        if (send (c, buf, n, 0) < 0) break;
    close (c);
    return NULL;
}

static void *
echo_thread (void *arg)
{
    (void)arg;
    int fd = socket (AF_INET, SOCK_STREAM, 0);
    int on = 1; setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    struct sockaddr_in a = { 0 };
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    a.sin_port = htons (TARGET_PORT);
    if (bind (fd, (struct sockaddr *)&a, sizeof a) < 0) { perror ("echo bind"); exit (2); }
    listen (fd, 8);
    while (echo_run) {
        fd_set r; FD_ZERO (&r); FD_SET (fd, &r);
        struct timeval tv = { 0, 200 * 1000 };
        if (select (fd + 1, &r, 0, 0, &tv) <= 0) continue;
        int c = accept (fd, 0, 0);
        if (c < 0) continue;
        pthread_t et; int *cp = malloc (sizeof (int)); *cp = c;
        if (pthread_create (&et, NULL, echo_conn, cp) == 0) pthread_detach (et);
        else { close (c); free (cp); }
    }
    close (fd);
    return NULL;
}

static void *run_pm (void *p) { portmux_run ((Portmux *)p); return NULL; }

static int
edge_roundtrip (int port, const char *msg)
{
    int fd = socket (AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { 0 };
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    a.sin_port = htons (port);
    struct timeval tv = { 6, 0 };
    setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    if (connect (fd, (struct sockaddr *)&a, sizeof a) < 0) { close (fd); return -1; }
    size_t L = strlen (msg);
    if (send (fd, msg, L, 0) < 0) { close (fd); return -1; }
    char buf[256] = { 0 }; size_t got = 0;
    while (got < L) {
        ssize_t n = recv (fd, buf + got, sizeof buf - got, 0);
        if (n <= 0) break;
        got += (size_t)n;
    }
    close (fd);
    return (got == L && memcmp (buf, msg, L) == 0) ? 0 : -1;
}

int
main (void)
{
    pthread_t echo_tid;
    unsigned char psk[PM_TUNNEL_PSK_LEN];
    int failures = 0;

    memset (psk, 0x5a, sizeof psk);
    pthread_create (&echo_tid, NULL, echo_thread, NULL);
    usleep (200 * 1000);

    /* ── peers: peerA (relay) + peerB (terminal). Both are plain peers; which
         one connects the target depends on nhops in the OPENJ they receive. ── */
    Portmux *pA = portmux_new ();
    if (portmux_add_tunnel_peer (pA, "127.0.0.1", PEERA_PORT, psk,
                                 PM_TUNNEL_CIPHER_AESGCM, NULL) < 0) {
        fprintf (stderr, "add peerA failed\n"); return 1;
    }
    Portmux *pB = portmux_new ();
    if (portmux_add_tunnel_peer (pB, "127.0.0.1", PEERB_PORT, psk,
                                 PM_TUNNEL_CIPHER_AESGCM, NULL) < 0) {
        fprintf (stderr, "add peerB failed\n"); return 1;
    }
    pthread_t ta, tb;
    pthread_create (&ta, NULL, run_pm, pA);
    pthread_create (&tb, NULL, run_pm, pB);
    usleep (300 * 1000);

    /* ── 2-hop edge: carrier to peerA; jumps=[A], target. peerA is terminal. ── */
    Portmux *e2 = portmux_new ();
    portmux_add_tunnel_client (e2, "127.0.0.1", EDGE2_PORT,
                               "127.0.0.1", PEERA_PORT,
                               "127.0.0.1", 0, psk,   /* target unused in jump mode */
                               PM_TUNNEL_CIPHER_AESGCM, NULL);
    {
        PmJumpEndpoint hops[1];
        memset (hops, 0, sizeof hops);
        snprintf (hops[0].addr, sizeof hops[0].addr, "127.0.0.1"); hops[0].port = PEERA_PORT;
        if (portmux_tunnel_set_jumps (e2, hops, 1, "127.0.0.1", TARGET_PORT,
                                      PM_MUX_PROTO_TCP) < 0) {
            fprintf (stderr, "set_jumps 2-hop failed\n"); return 1;
        }
    }
    pthread_t te2; pthread_create (&te2, NULL, run_pm, e2);
    usleep (600 * 1000);

    fprintf (stderr, "-> 2-hop: edge -> peerA -> target\n");
    int r2 = edge_roundtrip (EDGE2_PORT, "two-hop-jump-message");
    if (r2 == 0) printf ("2-HOP OK: echoed through edge->peerA->target\n");
    else { printf ("2-HOP FAIL\n"); failures++; }

    /* ── 3-hop edge: carrier to peerA; jumps=[A,B], target. peerA relays to
         peerB, which is terminal. ── */
    Portmux *e3 = portmux_new ();
    portmux_add_tunnel_client (e3, "127.0.0.1", EDGE3_PORT,
                               "127.0.0.1", PEERA_PORT,
                               "127.0.0.1", 0, psk,
                               PM_TUNNEL_CIPHER_AESGCM, NULL);
    {
        PmJumpEndpoint hops[2];
        memset (hops, 0, sizeof hops);
        snprintf (hops[0].addr, sizeof hops[0].addr, "127.0.0.1"); hops[0].port = PEERA_PORT;
        snprintf (hops[1].addr, sizeof hops[1].addr, "127.0.0.1"); hops[1].port = PEERB_PORT;
        if (portmux_tunnel_set_jumps (e3, hops, 2, "127.0.0.1", TARGET_PORT,
                                      PM_MUX_PROTO_TCP) < 0) {
            fprintf (stderr, "set_jumps 3-hop failed\n"); return 1;
        }
    }
    pthread_t te3; pthread_create (&te3, NULL, run_pm, e3);
    usleep (700 * 1000);

    fprintf (stderr, "-> 3-hop: edge -> peerA -> peerB -> target\n");
    int r3 = edge_roundtrip (EDGE3_PORT, "three-hop-jump-message-over-overlay");
    if (r3 == 0) printf ("3-HOP OK: echoed through edge->peerA->peerB->target\n");
    else { printf ("3-HOP FAIL\n"); failures++; }

    /* second message on the 3-hop path to exercise steady-state relay */
    int r3b = edge_roundtrip (EDGE3_PORT, "second-three-hop-message");
    if (r3b == 0) printf ("3-HOP-2 OK: second message echoed\n");
    else { printf ("3-HOP-2 FAIL\n"); failures++; }

    portmux_stop (e2); pthread_join (te2, NULL); portmux_destroy (e2);
    portmux_stop (e3); pthread_join (te3, NULL); portmux_destroy (e3);
    portmux_stop (pA); pthread_join (ta, NULL); portmux_destroy (pA);
    portmux_stop (pB); pthread_join (tb, NULL); portmux_destroy (pB);
    echo_run = 0; pthread_join (echo_tid, NULL);

    if (failures) { printf ("RESULT: %d failure(s)\n", failures); return 1; }
    printf ("JUMP OK: multi-hop source routing verified (2-hop + 3-hop)\n");
    printf ("RESULT: all passed\n");
    return 0;
}
