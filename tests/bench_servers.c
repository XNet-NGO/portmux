/* Benchmark servers: TCP sink, TCP echo, UDP echo. Ports from argv.
 *   bench_servers SINK_PORT ECHO_PORT UDP_PORT
 * Runs until killed. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

static int SINK, ECHO, UDP;

static int
listen_on (int port)
{
    int fd = socket (AF_INET, SOCK_STREAM, 0), on = 1;
    setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    struct sockaddr_in s = { 0 };
    s.sin_family = AF_INET; s.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    s.sin_port = htons (port);
    bind (fd, (void *)&s, sizeof s); listen (fd, 64);
    return fd;
}

static void *
sink_t (void *a)
{
    (void)a; int fd = listen_on (SINK);
    for (;;) {
        int c = accept (fd, NULL, NULL);
        if (c < 0) continue;
        char *b = malloc (1 << 20);
        while (recv (c, b, 1 << 20, 0) > 0) { }
        free (b); close (c);
    }
}

static void *
echo_t (void *a)
{
    (void)a; int fd = listen_on (ECHO), on = 1;
    for (;;) {
        int c = accept (fd, NULL, NULL);
        if (c < 0) continue;
        setsockopt (c, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
        char b[256]; ssize_t n;
        while ((n = recv (c, b, sizeof b, 0)) > 0)
            if (send (c, b, n, 0) < 0) break;
        close (c);
    }
}

static void *
udp_t (void *a)
{
    (void)a;
    int fd = socket (AF_INET, SOCK_DGRAM, 0), on = 1;
    setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    struct sockaddr_in s = { 0 };
    s.sin_family = AF_INET; s.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    s.sin_port = htons (UDP);
    bind (fd, (void *)&s, sizeof s);
    for (;;) {
        char b[2048]; struct sockaddr_in from; socklen_t fl = sizeof from;
        ssize_t n = recvfrom (fd, b, sizeof b, 0, (void *)&from, &fl);
        if (n > 0) sendto (fd, b, n, 0, (void *)&from, fl);
    }
}

int
main (int argc, char **argv)
{
    if (argc < 4) { fprintf (stderr, "usage: %s SINK ECHO UDP\n", argv[0]); return 1; }
    SINK = atoi (argv[1]); ECHO = atoi (argv[2]); UDP = atoi (argv[3]);
    pthread_t a, b, c;
    pthread_create (&a, NULL, sink_t, NULL);
    pthread_create (&b, NULL, echo_t, NULL);
    pthread_create (&c, NULL, udp_t, NULL);
    pthread_join (a, NULL);
    return 0;
}
