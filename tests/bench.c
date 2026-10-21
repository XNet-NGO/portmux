/* Loopback benchmark CLIENT for portmux.
 *
 *   bench THROUGHPUT_PORT  LATENCY_PORT  UDP_PORT  LABEL
 *
 * Connects to the given ports (point them at real servers for "direct", or at
 * portmux listen ports for "relayed") and measures:
 *   - TCP bulk throughput  (GB/s)         over THROUGHPUT_PORT  (sink server)
 *   - TCP req/resp latency (round trips/s) over LATENCY_PORT    (echo server)
 *   - UDP packet rate      (pkts/s)        over UDP_PORT        (echo server)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

static double
now_s (void)
{
    struct timespec t;
    clock_gettime (CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static int
conn (int port)
{
    int fd = socket (AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in s = { 0 };
    s.sin_family = AF_INET;
    s.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    s.sin_port = htons (port);
    if (connect (fd, (void *)&s, sizeof s) < 0) {
        perror ("connect");
        exit (2);
    }
    return fd;
}

int
main (int argc, char **argv)
{
    if (argc < 5) {
        fprintf (stderr, "usage: %s TPUT_PORT LAT_PORT UDP_PORT LABEL\n", argv[0]);
        return 1;
    }
    int tput_port = atoi (argv[1]);
    int lat_port = atoi (argv[2]);
    int udp_port = atoi (argv[3]);
    const char *label = argv[4];

    printf ("== %s ==\n", label);

    /* ---- TCP throughput: blast to a sink for ~3s ---- */
    {
        int fd = conn (tput_port);
        size_t chunk = 256 * 1024;
        char *buf = calloc (1, chunk);
        double t0 = now_s (), t1;
        unsigned long long bytes = 0;
        do {
            ssize_t s = send (fd, buf, chunk, 0);
            if (s > 0) bytes += s;
            t1 = now_s ();
        } while (t1 - t0 < 3.0);
        double gbps = (bytes / (t1 - t0)) / 1e9;
        printf ("  TCP throughput : %.2f GB/s  (%.1f Gbit/s)\n", gbps, gbps * 8);
        free (buf);
        close (fd);
    }

    /* ---- TCP latency: ping-pong 1-byte for ~2s ---- */
    {
        int fd = conn (lat_port);
        int on = 1;
        setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
        char b = 'x', r;
        double t0 = now_s (), t1;
        unsigned long long rt = 0;
        do {
            if (send (fd, &b, 1, 0) != 1) break;
            if (recv (fd, &r, 1, 0) != 1) break;
            rt++;
            t1 = now_s ();
        } while (t1 - t0 < 2.0);
        double rps = rt / (t1 - t0);
        printf ("  TCP latency    : %.0f round-trips/s  (%.1f us/RT)\n",
                rps, 1e6 / rps);
        close (fd);
    }

    /* ---- UDP packet rate: send+recv 64B datagrams for ~2s ---- */
    {
        int fd = socket (AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in s = { 0 };
        s.sin_family = AF_INET;
        s.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
        s.sin_port = htons (udp_port);
        connect (fd, (void *)&s, sizeof s);
        struct timeval tv = { 1, 0 };
        setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        char b[64] = { 0 }, r[64];
        double t0 = now_s (), t1;
        unsigned long long pk = 0;
        do {
            if (send (fd, b, sizeof b, 0) != sizeof b) break;
            if (recv (fd, r, sizeof r, 0) != sizeof r) break;
            pk++;
            t1 = now_s ();
        } while (t1 - t0 < 2.0);
        double pps = pk / (t1 - t0);
        printf ("  UDP pkt rate   : %.0f pkt/s round-trip  (%.1f us/pkt)\n",
                pps, 1e6 / pps);
        close (fd);
    }

    return 0;
}
