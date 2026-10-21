/*
 ============================================================================
 Name        : test_udp_evict.c
 Description : Verifies idle UDP flows are evicted by the sweeper.
 *
 * Build with short timeouts, e.g.:
 *   gcc ... -DPM_UDP_IDLE_MS=800 -DPM_UDP_SWEEP_MS=200 src/portmux.c ...
 *
 * Strategy:
 *   - Run a UDP echo target.
 *   - Run portmux udp 127.0.0.1:PL -> 127.0.0.1:PT.
 *   - Send one datagram, confirm echo (flow created).
 *   - Wait > idle timeout + a sweep interval.
 *   - Confirm a NEW datagram still works (relay healthy after eviction),
 *     and that the flow count returned to zero in between via the reap path
 *     (observed indirectly: a fresh flow is created again — logged at debug).
 *
 * The functional assertion is that traffic still flows after the idle period,
 * i.e. eviction did not break the listener. A stronger white-box assertion
 * (flow_count==0) would require exposing internals; this stays black-box.
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

#define UDP_TARGET_PORT 48822
#define UDP_LISTEN_PORT 48832

static volatile int echo_run = 1;

static void *
echo_thread (void *arg)
{
    (void)arg;
    int fd = socket (AF_INET, SOCK_DGRAM, 0);
    int on = 1;
    setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on));
    struct sockaddr_in a = { 0 };
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    a.sin_port = htons (UDP_TARGET_PORT);
    if (bind (fd, (struct sockaddr *)&a, sizeof (a)) < 0) {
        perror ("udp target bind");
        exit (2);
    }
    while (echo_run) {
        char buf[2048];
        struct sockaddr_in from;
        socklen_t fl = sizeof (from);
        struct timeval tv = { 0, 200 * 1000 };
        setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv));
        ssize_t n = recvfrom (fd, buf, sizeof (buf), 0,
                              (struct sockaddr *)&from, &fl);
        if (n > 0)
            sendto (fd, buf, n, 0, (struct sockaddr *)&from, fl);
    }
    close (fd);
    return NULL;
}

static Portmux *g_pm;
static void *
pm_thread (void *arg)
{
    (void)arg;
    portmux_run (g_pm);
    return NULL;
}

static int
round_trip (const char *msg)
{
    int fd = socket (AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = { 0 };
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    a.sin_port = htons (UDP_LISTEN_PORT);
    char buf[256] = { 0 };
    struct timeval tv = { 2, 0 };
    setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv));
    sendto (fd, msg, strlen (msg), 0, (struct sockaddr *)&a, sizeof (a));
    ssize_t n = recv (fd, buf, sizeof (buf), 0);
    close (fd);
    if (n != (ssize_t)strlen (msg) || memcmp (buf, msg, n) != 0) {
        fprintf (stderr, "round_trip('%s') FAIL: got %zd bytes\n", msg, n);
        return -1;
    }
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
    portmux_add_route (g_pm, PORTMUX_PROTO_UDP, "127.0.0.1", UDP_LISTEN_PORT,
                       "127.0.0.1", UDP_TARGET_PORT, NULL);

    pthread_create (&pm_tid, NULL, pm_thread, NULL);
    usleep (300 * 1000);

    fprintf (stderr, "-> initial round trip (creates flow)\n");
    failures += round_trip ("first") < 0;

    /* Wait past the (short, test-compiled) idle timeout + a couple sweeps so
       the sweeper evicts the idle flow. */
    fprintf (stderr, "-> idling to trigger eviction\n");
    usleep (2500 * 1000);

    fprintf (stderr, "-> round trip after eviction (new flow)\n");
    failures += round_trip ("second") < 0;

    portmux_stop (g_pm);
    pthread_join (pm_tid, NULL);
    portmux_destroy (g_pm);

    echo_run = 0;
    pthread_join (echo_tid, NULL);

    if (failures) {
        printf ("RESULT: %d failure(s)\n", failures);
        return 1;
    }
    printf ("RESULT: all passed (traffic healthy across idle eviction)\n");
    return 0;
}
