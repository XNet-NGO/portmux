/*
 ============================================================================
 Name        : test_rjump.c
 Description : End-to-end REVERSE multi-hop jump routing over the Noise tunnel.
 *
 * The mirror of test_jump.c. In FORWARD jump the EDGE accepts a local client
 * and source-routes it to a terminal target. In REVERSE jump the EDGE (the
 * phone, behind CGNAT) still DIALS OUT to build the carrier chain, but a client
 * accepted at the TERMINAL end travels BACK UP the chain to the edge, which
 * dials its OWN local target (e.g. adbd). Nothing ever dials INTO the edge.
 *
 *   test (runner)  ->  TERMINAL reverse-listener (:RLISTEN)
 *                         ^  (origin-set stream travels back up)
 *                         |  peerB <- peerA  (carriers dialed by the edge)
 *                         |
 *                       EDGE (client, dialed out)  -> reverse target (echo)
 *
 * Topology, all on 127.0.0.1, each portmux instance on its own thread:
 *   - 2 hops: edge -> peerA(terminal, rlisten)                 (jumps=[A])
 *   - 3 hops: edge -> peerA -> peerB(terminal, rlisten)        (jumps=[A,B])
 *
 * The EDGE is a tunnel-client with PM_JUMPS set AND a reverse target
 * (portmux_tunnel_set_reverse_target -> the echo server). The TERMINAL peer
 * opens a plain reverse listener; a connection there originates a reverse
 * stream that is relayed hop-by-hop back to the edge, which connects the echo
 * target and splices. Asserts bytes echo back through the full reverse path.
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

#define TARGET_PORT 49401   /* edge's reverse target (echo) */
#define PEERA_PORT  49411
#define PEERB_PORT  49412
#define RLISTEN2_PORT 49421 /* terminal reverse listener for the 2-hop test */
#define RLISTEN3_PORT 49422 /* terminal reverse listener for the 3-hop test */

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

/* Connect to the TERMINAL's reverse listener, send msg, expect it echoed back
   (the echo happens at the EDGE's reverse target after the reverse chain). */
static int
rlisten_roundtrip (int port, const char *msg)
{
    int fd = socket (AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { 0 };
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    a.sin_port = htons (port);
    struct timeval tv = { 8, 0 };
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

    /* ── 2-hop: edge -> peerA(terminal+rlisten). peerA opens the reverse
         listener :RLISTEN2_PORT; a connection there travels back to the edge. ─ */
    Portmux *pA = portmux_new ();
    if (portmux_add_tunnel_peer (pA, "127.0.0.1", PEERA_PORT, psk,
                                 PM_TUNNEL_CIPHER_AESGCM, NULL) < 0) {
        fprintf (stderr, "add peerA failed\n"); return 1;
    }
    /* terminal reverse listener on peerA for the 2-hop test */
    if (portmux_tunnel_peer_set_rlisten (pA, "127.0.0.1", RLISTEN2_PORT, 0) < 0) {
        fprintf (stderr, "peerA set_rlisten failed\n"); return 1;
    }

    Portmux *pB = portmux_new ();
    if (portmux_add_tunnel_peer (pB, "127.0.0.1", PEERB_PORT, psk,
                                 PM_TUNNEL_CIPHER_AESGCM, NULL) < 0) {
        fprintf (stderr, "add peerB failed\n"); return 1;
    }
    /* terminal reverse listener on peerB for the 3-hop test */
    if (portmux_tunnel_peer_set_rlisten (pB, "127.0.0.1", RLISTEN3_PORT, 0) < 0) {
        fprintf (stderr, "peerB set_rlisten failed\n"); return 1;
    }

    pthread_t ta, tb;
    pthread_create (&ta, NULL, run_pm, pA);
    pthread_create (&tb, NULL, run_pm, pB);
    usleep (300 * 1000);

    /* ── 2-hop edge: carrier to peerA; jumps=[A]; reverse target = echo. The
         edge dials out; the reverse stream originates at peerA's rlisten. ── */
    Portmux *e2 = portmux_new ();
    portmux_add_tunnel_client (e2, NULL, 0,
                               "127.0.0.1", PEERA_PORT,
                               "127.0.0.1", 0, psk,
                               PM_TUNNEL_CIPHER_AESGCM, NULL);
    /* reverse target: where the EDGE connects on a reverse OPEN that arrives
       back up the chain (the echo server). */
    portmux_tunnel_set_reverse_target (e2, "127.0.0.1", TARGET_PORT);
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
    usleep (700 * 1000);

    fprintf (stderr, "-> reverse 2-hop: runner -> peerA(rlisten) ~> edge -> target\n");
    int r2 = rlisten_roundtrip (RLISTEN2_PORT, "reverse-two-hop-message");
    if (r2 == 0) printf ("R2-HOP OK: echoed back up edge<-peerA\n");
    else { printf ("R2-HOP FAIL\n"); failures++; }

    /* ── 3-hop edge: carrier to peerA; jumps=[A,B]; reverse target = echo.
         peerB is terminal (rlisten :RLISTEN3_PORT). ── */
    Portmux *e3 = portmux_new ();
    portmux_add_tunnel_client (e3, NULL, 0,
                               "127.0.0.1", PEERA_PORT,
                               "127.0.0.1", 0, psk,
                               PM_TUNNEL_CIPHER_AESGCM, NULL);
    portmux_tunnel_set_reverse_target (e3, "127.0.0.1", TARGET_PORT);
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
    usleep (900 * 1000);

    fprintf (stderr, "-> reverse 3-hop: runner -> peerB(rlisten) ~> peerA ~> edge -> target\n");
    int r3 = rlisten_roundtrip (RLISTEN3_PORT, "reverse-three-hop-message-over-overlay");
    if (r3 == 0) printf ("R3-HOP OK: echoed back up edge<-peerA<-peerB\n");
    else { printf ("R3-HOP FAIL\n"); failures++; }

    /* steady-state: a second reverse message on the 3-hop path */
    int r3b = rlisten_roundtrip (RLISTEN3_PORT, "second-reverse-three-hop-message");
    if (r3b == 0) printf ("R3-HOP-2 OK: second reverse message echoed\n");
    else { printf ("R3-HOP-2 FAIL\n"); failures++; }

    portmux_stop (e2); pthread_join (te2, NULL); portmux_destroy (e2);
    portmux_stop (e3); pthread_join (te3, NULL); portmux_destroy (e3);
    portmux_stop (pA); pthread_join (ta, NULL); portmux_destroy (pA);
    portmux_stop (pB); pthread_join (tb, NULL); portmux_destroy (pB);
    echo_run = 0; pthread_join (echo_tid, NULL);

    if (failures) { printf ("RESULT: %d failure(s)\n", failures); return 1; }
    printf ("RJUMP OK: reverse multi-hop source routing verified (2-hop + 3-hop)\n");
    printf ("RESULT: all passed\n");
    return 0;
}
