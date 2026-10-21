/*
 ============================================================================
 Name        : portmux.c
 Description : Core forwarder: listeners, TCP splice, UDP flow relay.
 ============================================================================
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
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
#include "portmux-egress.h"

int portmux_log_level = 3;

#define PM_MAX_ROUTES 64
#define PM_TCP_SPLICE_BUF (256 * 1024)
#define PM_UDP_DGRAM_MAX 65536
#ifndef PM_UDP_IDLE_MS
#define PM_UDP_IDLE_MS 60000
#endif
#ifndef PM_UDP_SWEEP_MS
#define PM_UDP_SWEEP_MS 5000
#endif
#define PM_UDP_MAX_FLOWS 1024

struct _PortmuxRoute
{
    PortmuxProto proto;
    char listen_addr[128];
    int listen_port;
    char target_addr[128];
    int target_port;
    PortmuxEgress egress;
    int egress_valid;

    Portmux *owner;
    int listen_fd;
};

/* Registry node: every long-running task links itself here so shutdown can
   wake tasks parked in WAITIO (setting run=0 alone does not wake them). */
typedef struct PmTaskNode PmTaskNode;
struct PmTaskNode
{
    PmTaskNode *next;
    PmTaskNode *prev;
    HevTask *task;
};

struct _Portmux
{
    PortmuxRoute routes[PM_MAX_ROUTES];
    int route_count;

    volatile int run;
    int opened;
    int event_fds[2]; /* [0] read in event task, [1] written by stop() */

    PmTaskNode *tasks; /* head of live-task registry (single-thread access) */
};

/* ─────────────────── task registry (cooperative) ───────────── */

static void
pm_task_register (Portmux *self, PmTaskNode *node)
{
    node->task = hev_task_self ();
    node->prev = NULL;
    node->next = self->tasks;
    if (self->tasks)
        self->tasks->prev = node;
    self->tasks = node;
}

static void
pm_task_unregister (Portmux *self, PmTaskNode *node)
{
    if (node->prev)
        node->prev->next = node->next;
    else
        self->tasks = node->next;
    if (node->next)
        node->next->prev = node->prev;
    node->next = node->prev = NULL;
}

static void
pm_wake_all_tasks (Portmux *self)
{
    PmTaskNode *n;
    for (n = self->tasks; n; n = n->next)
        hev_task_wakeup (n->task);
}

/* ───────────────────────── yielders ───────────────────────── */

static int
run_yielder (HevTaskYieldType type, void *data)
{
    Portmux *self = data;
    hev_task_yield (type);
    return self->run ? 0 : -1;
}

/* Monotonic milliseconds for idle-flow accounting. */
static unsigned long
mono_ms (void)
{
    struct timespec ts;
    clock_gettime (CLOCK_MONOTONIC, &ts);
    return (unsigned long)ts.tv_sec * 1000UL + (unsigned long)ts.tv_nsec / 1000000UL;
}

/* Disable Nagle so small request/response messages are not delayed. Critical
   for latency-sensitive relays (MCP control, DAW<->VST messaging). */
static void
set_nodelay (int fd)
{
    int on = 1;
    setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof (on));
}

/* ─────────────────────── TCP forwarding ────────────────────── */

typedef struct
{
    Portmux *owner;
    PortmuxRoute *route;
    int client_fd;
} PmTcpConn;

static void
tcp_conn_task (void *data)
{
    PmTcpConn *c = data;
    PortmuxRoute *r = c->route;
    struct sockaddr_storage ss;
    socklen_t sslen;
    int family, up_fd, res;
    PmTaskNode node;

    pm_task_register (c->owner, &node);

    family = portmux_resolve (r->target_addr, r->target_port, SOCK_STREAM, 0,
                              &ss, &sslen);
    if (family < 0)
        goto close_client;

    up_fd = hev_task_io_socket_socket (family, SOCK_STREAM, 0);
    if (up_fd < 0) {
        PM_LOG_W ("tcp: upstream socket: %s", strerror (errno));
        goto close_client;
    }

    if (portmux_egress_apply (up_fd, family,
                              r->egress_valid ? &r->egress : NULL) < 0) {
        close (up_fd);
        goto close_client;
    }

    hev_task_add_fd (hev_task_self (), up_fd, POLLIN | POLLOUT);

    res = hev_task_io_socket_connect (up_fd, (struct sockaddr *)&ss, sslen,
                                      run_yielder, c->owner);
    if (res < 0) {
        PM_LOG_I ("tcp: connect %s:%d failed", r->target_addr, r->target_port);
        hev_task_del_fd (hev_task_self (), up_fd);
        close (up_fd);
        goto close_client;
    }

    PM_LOG_D ("tcp: %d <-> %s:%d established", c->client_fd, r->target_addr,
              r->target_port);

    set_nodelay (up_fd);
    set_nodelay (c->client_fd);

    /* Both fds must be in the task reactor for the splice to wake on I/O. */
    hev_task_add_fd (hev_task_self (), c->client_fd, POLLIN | POLLOUT);

    /* Bidirectional splice with backpressure (vendored, lwIP-free). */
    hev_task_io_splice (c->client_fd, c->client_fd, up_fd, up_fd,
                        PM_TCP_SPLICE_BUF, run_yielder, c->owner);

    hev_task_del_fd (hev_task_self (), up_fd);
    close (up_fd);

close_client:
    hev_task_del_fd (hev_task_self (), c->client_fd);
    close (c->client_fd);
    free (c);
    pm_task_unregister (r->owner, &node);
}

static void
tcp_listen_task (void *data)
{
    PortmuxRoute *r = data;
    Portmux *self = r->owner;
    PmTaskNode node;

    pm_task_register (self, &node);
    PM_LOG_D ("tcp: listen task started fd=%d", r->listen_fd);
    hev_task_add_fd (hev_task_self (), r->listen_fd, POLLIN);

    while (self->run) {
        struct sockaddr_storage peer;
        socklen_t plen = sizeof (peer);
        PmTcpConn *c;
        HevTask *task;
        int cfd;

        cfd = hev_task_io_socket_accept (r->listen_fd, (struct sockaddr *)&peer,
                                         &plen, run_yielder, self);
        if (cfd == -2) /* yielder signalled shutdown */
            break;
        if (cfd < 0)
            continue;

        c = calloc (1, sizeof (PmTcpConn));
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
        hev_task_run (task, tcp_conn_task, c);
    }

    hev_task_del_fd (hev_task_self (), r->listen_fd);
    close (r->listen_fd);
    pm_task_unregister (self, &node);
}

/* ─────────────────────── UDP forwarding ────────────────────── */
/*
 * One listener socket. A flow is keyed by the client's source address.
 * Each flow owns an upstream UDP socket connected to the target; a per-flow
 * task pumps upstream->client and refreshes an idle deadline. Client->upstream
 * datagrams are pushed from the listener task.
 */

typedef struct PmUdpFlow PmUdpFlow;
struct PmUdpFlow
{
    PmUdpFlow *next;
    struct sockaddr_storage peer; /* client source */
    socklen_t peer_len;
    int up_fd;                    /* connected to target */
    int listen_fd;                /* shared, for replying to client */
    Portmux *owner;
    HevTask *task;
    unsigned long last_ms;        /* last activity (monotonic ms) */
    int evict;                    /* set by sweeper to request shutdown */
    int done;                     /* set as the flow task's final act */
};

typedef struct
{
    PortmuxRoute *route;
    Portmux *owner;
    PmUdpFlow *flows;
    int flow_count;
    int sweeper_run;       /* 1 while the sweeper should keep running */
    int sweeper_done;      /* set by sweeper as its final act */
    HevTask *sweeper_task;
} PmUdpState;

static int
sockaddr_eq (const struct sockaddr_storage *a, socklen_t al,
             const struct sockaddr_storage *b, socklen_t bl)
{
    if (al != bl)
        return 0;
    return memcmp (a, b, al) == 0;
}

/* Pumps target -> client. Cooperative scheduling means no preemption; the
   flow only frees-safe boundary is: it never touches *f after setting done=1,
   and the listener only frees flows with done==1. */
static int
flow_yielder (HevTaskYieldType type, void *data)
{
    PmUdpFlow *f = data;
    hev_task_yield (type);
    return (f->owner->run && !f->evict) ? 0 : -1;
}

static void
udp_flow_task (void *data)
{
    PmUdpFlow *f = data;
    char *buf = malloc (PM_UDP_DGRAM_MAX);
    PmTaskNode node;

    if (!buf) {
        f->done = 1;
        return;
    }

    pm_task_register (f->owner, &node);
    hev_task_add_fd (hev_task_self (), f->up_fd, POLLIN);

    while (f->owner->run && !f->evict) {
        ssize_t n = hev_task_io_socket_recv (f->up_fd, buf, PM_UDP_DGRAM_MAX, 0,
                                             flow_yielder, f);
        if (n == -2)
            break;
        if (n == 0)
            break;
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            break;
        }
        /* upstream -> client via the shared listener socket */
        sendto (f->listen_fd, buf, n, 0, (struct sockaddr *)&f->peer,
                f->peer_len);
        f->last_ms = mono_ms ();
    }

    free (buf);
    hev_task_del_fd (hev_task_self (), f->up_fd);
    close (f->up_fd);
    f->up_fd = -1;
    pm_task_unregister (f->owner, &node);
    f->done = 1; /* MUST be last: *f may be freed by listener after this */
}

static PmUdpFlow *
udp_find_flow (PmUdpState *st, const struct sockaddr_storage *peer,
               socklen_t plen)
{
    PmUdpFlow *f;
    for (f = st->flows; f; f = f->next) {
        if (!f->done && sockaddr_eq (&f->peer, f->peer_len, peer, plen))
            return f;
    }
    return NULL;
}

static void
udp_reap_done (PmUdpState *st)
{
    PmUdpFlow **pp = &st->flows;
    while (*pp) {
        PmUdpFlow *f = *pp;
        if (f->done) {
            *pp = f->next;
            free (f);
            st->flow_count--;
        } else {
            pp = &f->next;
        }
    }
}

static PmUdpFlow *
udp_new_flow (PmUdpState *st, const struct sockaddr_storage *peer,
              socklen_t plen)
{
    PortmuxRoute *r = st->route;
    struct sockaddr_storage tss;
    socklen_t tlen;
    PmUdpFlow *f;
    HevTask *task;
    int family, up_fd;

    if (st->flow_count >= PM_UDP_MAX_FLOWS) {
        udp_reap_done (st);
        if (st->flow_count >= PM_UDP_MAX_FLOWS)
            return NULL;
    }

    family = portmux_resolve (r->target_addr, r->target_port, SOCK_DGRAM, 0,
                              &tss, &tlen);
    if (family < 0)
        return NULL;

    up_fd = hev_task_io_socket_socket (family, SOCK_DGRAM, 0);
    if (up_fd < 0)
        return NULL;

    if (portmux_egress_apply (up_fd, family,
                              r->egress_valid ? &r->egress : NULL) < 0) {
        close (up_fd);
        return NULL;
    }

    /* connect() the UDP socket so recv() only yields target replies. */
    if (connect (up_fd, (struct sockaddr *)&tss, tlen) < 0) {
        PM_LOG_W ("udp: connect target %s:%d: %s", r->target_addr,
                  r->target_port, strerror (errno));
        close (up_fd);
        return NULL;
    }

    f = calloc (1, sizeof (PmUdpFlow));
    if (!f) {
        close (up_fd);
        return NULL;
    }
    memcpy (&f->peer, peer, plen);
    f->peer_len = plen;
    f->up_fd = up_fd;
    f->listen_fd = r->listen_fd;
    f->owner = st->owner;
    f->last_ms = mono_ms ();
    f->evict = 0;
    f->done = 0;

    f->next = st->flows;
    st->flows = f;
    st->flow_count++;

    task = hev_task_new (-1);
    if (!task) {
        close (up_fd);
        f->up_fd = -1;
        f->done = 1; /* will be reaped */
        return NULL;
    }
    f->task = task;
    hev_task_run (task, udp_flow_task, f);

    return f;
}

/* Periodically evicts idle flows. Runs as its own task; shares the listener's
   PmUdpState (cooperative scheduling => no locking). Only marks flows for
   eviction and wakes their tasks; the listener task frees them. */
static void
udp_sweeper_task (void *data)
{
    PmUdpState *st = data;
    PmTaskNode node;

    pm_task_register (st->owner, &node);

    while (st->owner->run && st->sweeper_run) {
        unsigned long now;
        PmUdpFlow *f;
        int slept;

        /* Sleep in small slices so shutdown is responsive. hev_task_sleep
           returns early if the task is woken. */
        unsigned slice = PM_UDP_SWEEP_MS < 500 ? PM_UDP_SWEEP_MS : 500;
        slept = 0;
        while (slept < PM_UDP_SWEEP_MS && st->owner->run && st->sweeper_run) {
            hev_task_sleep (slice);
            slept += slice;
        }
        if (!st->owner->run || !st->sweeper_run)
            break;

        now = mono_ms ();
        for (f = st->flows; f; f = f->next) {
            if (f->done || f->evict)
                continue;
            if (now - f->last_ms >= PM_UDP_IDLE_MS) {
                PM_LOG_D ("udp: evicting idle flow (idle %lums)",
                          now - f->last_ms);
                f->evict = 1;
                if (f->task)
                    hev_task_wakeup (f->task);
            }
        }
    }

    pm_task_unregister (st->owner, &node);
    st->sweeper_done = 1; /* MUST be last: *st may go away after this */
}

static void
udp_listen_task (void *data)
{
    PortmuxRoute *r = data;
    Portmux *self = r->owner;
    PmUdpState st = { 0 };
    char *buf = malloc (PM_UDP_DGRAM_MAX);
    PmTaskNode node;

    if (!buf) {
        PM_LOG_E ("udp: buffer alloc failed");
        close (r->listen_fd);
        return;
    }

    pm_task_register (self, &node);
    st.route = r;
    st.owner = self;

    PM_LOG_D ("udp: listen task started fd=%d", r->listen_fd);
    hev_task_add_fd (hev_task_self (), r->listen_fd, POLLIN);

    /* Spawn the idle-flow sweeper. */
    st.sweeper_run = 1;
    st.sweeper_done = 0;
    st.sweeper_task = hev_task_new (-1);
    if (st.sweeper_task)
        hev_task_run (st.sweeper_task, udp_sweeper_task, &st);
    else
        st.sweeper_done = 1; /* nothing to wait for */

    while (self->run) {
        struct sockaddr_storage peer;
        socklen_t plen = sizeof (peer);
        PmUdpFlow *f;
        ssize_t n;

        n = hev_task_io_socket_recvfrom (r->listen_fd, buf, PM_UDP_DGRAM_MAX, 0,
                                         (struct sockaddr *)&peer, &plen,
                                         run_yielder, self);
        if (n == -2)
            break;
        if (n <= 0)
            continue;

        f = udp_find_flow (&st, &peer, plen);
        if (!f) {
            f = udp_new_flow (&st, &peer, plen);
            if (!f)
                continue;
            PM_LOG_D ("udp: new flow -> %s:%d (flows=%d)", r->target_addr,
                      r->target_port, st.flow_count);
        }

        /* client -> upstream (socket is connected to target) */
        if (f->up_fd >= 0) {
            (void)send (f->up_fd, buf, n, 0);
            f->last_ms = mono_ms ();
        }

        udp_reap_done (&st);
    }

    /* stop the sweeper first so it stops touching the flow list */
    st.sweeper_run = 0;
    if (st.sweeper_task && !st.sweeper_done)
        hev_task_wakeup (st.sweeper_task);

    /* teardown: wake all flow tasks so they observe run==0 and exit, then
       yield until they finish, then free. */
    {
        PmUdpFlow *f;
        for (f = st.flows; f; f = f->next) {
            if (!f->done && f->task)
                hev_task_wakeup (f->task);
        }
        /* let flow tasks run their exit path */
        while (st.flows) {
            int any_live = 0;
            for (f = st.flows; f; f = f->next)
                if (!f->done)
                    any_live = 1;
            if (!any_live)
                break;
            hev_task_yield (HEV_TASK_YIELD);
        }
        udp_reap_done (&st);
    }

    /* ensure the sweeper has fully exited before st goes out of scope.
       It was already woken above; it will also wake from its own sleep
       slice and observe sweeper_run==0. Do NOT wake it here: once it exits,
       hev_task_run has consumed its reference and the handle is dangling. */
    while (!st.sweeper_done)
        hev_task_yield (HEV_TASK_YIELD);

    free (buf);
    hev_task_del_fd (hev_task_self (), r->listen_fd);
    close (r->listen_fd);
    pm_task_unregister (self, &node);
}

/* ──────────────────────── listeners ────────────────────────── */

static int
open_listener (PortmuxRoute *r)
{
    struct sockaddr_storage ss;
    socklen_t sslen;
    int socktype = (r->proto == PORTMUX_PROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM;
    int family, fd, on = 1;

    family = portmux_resolve (r->listen_addr, r->listen_port, socktype, 1, &ss,
                              &sslen);
    if (family < 0)
        return -1;

    fd = hev_task_io_socket_socket (family, socktype, 0);
    if (fd < 0) {
        PM_LOG_E ("listener socket %s:%d: %s", r->listen_addr, r->listen_port,
                  strerror (errno));
        return -1;
    }

    setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on));

    if (bind (fd, (struct sockaddr *)&ss, sslen) < 0) {
        PM_LOG_E ("bind %s:%d: %s", r->listen_addr, r->listen_port,
                  strerror (errno));
        close (fd);
        return -1;
    }

    if (socktype == SOCK_STREAM) {
        if (listen (fd, 128) < 0) {
            PM_LOG_E ("listen %s:%d: %s", r->listen_addr, r->listen_port,
                      strerror (errno));
            close (fd);
            return -1;
        }
    }

    r->listen_fd = fd;
    return 0;
}

/* ──────────────────────── event task ───────────────────────── */

static void
event_task_entry (void *data)
{
    Portmux *self = data;
    char b;

    hev_task_add_fd (hev_task_self (), self->event_fds[0], POLLIN);
    /* Use the run_yielder so a spurious wake re-checks self->run instead of
       blocking; loop until a real stop byte arrives. */
    for (;;) {
        ssize_t n = hev_task_io_read (self->event_fds[0], &b, 1, run_yielder,
                                      self);
        if (n == 1)       /* stop requested */
            break;
        if (n == -2)      /* yielder aborted (already stopping) */
            break;
        if (n == 0)       /* peer closed */
            break;
        /* n < 0 with EAGAIN: run_yielder already yielded; loop. */
    }
    self->run = 0;
    pm_wake_all_tasks (self);
    hev_task_del_fd (hev_task_self (), self->event_fds[0]);
}

/* ────────────────────────── public ─────────────────────────── */

Portmux *
portmux_new (void)
{
    Portmux *self;

    /* NOTE: hev-task-system state is per-thread. init/run/fini must all
       happen on the thread that calls portmux_run(), so init is deferred
       to portmux_run() rather than done here. */
    self = calloc (1, sizeof (Portmux));
    if (!self)
        return NULL;
    self->event_fds[0] = -1;
    self->event_fds[1] = -1;
    return self;
}

int
portmux_add_route (Portmux *self, PortmuxProto proto, const char *listen_addr,
                   int listen_port, const char *target_addr, int target_port,
                   const PortmuxEgress *egress)
{
    PortmuxRoute *r;

    if (!self || self->route_count >= PM_MAX_ROUTES)
        return -1;

    r = &self->routes[self->route_count];
    memset (r, 0, sizeof (*r));
    r->proto = proto;
    snprintf (r->listen_addr, sizeof (r->listen_addr), "%s",
              listen_addr ? listen_addr : "0.0.0.0");
    r->listen_port = listen_port;
    snprintf (r->target_addr, sizeof (r->target_addr), "%s", target_addr);
    r->target_port = target_port;
    r->owner = self;
    r->listen_fd = -1;

    if (egress) {
        r->egress = *egress;
        r->egress_valid = 1;
    }

    self->route_count++;
    return 0;
}

/* Runs as the single bootstrap task. Opens listeners and spawns the event
   task plus one task per route. Must run inside the task system (spawning
   sibling tasks from the plain main context does not schedule reliably when
   those tasks park on I/O — see hev echo-server pattern). */
static void
bootstrap_task_entry (void *data)
{
    Portmux *self = data;
    int opened = 0;
    int i;
    HevTask *task;

    task = hev_task_new (-1);
    if (task)
        hev_task_run (task, event_task_entry, self);

    for (i = 0; i < self->route_count; i++) {
        PortmuxRoute *r = &self->routes[i];
        if (open_listener (r) < 0)
            continue;
        task = hev_task_new (-1);
        if (!task) {
            close (r->listen_fd);
            r->listen_fd = -1;
            continue;
        }
        if (r->proto == PORTMUX_PROTO_TCP)
            hev_task_run (task, tcp_listen_task, r);
        else
            hev_task_run (task, udp_listen_task, r);
        PM_LOG_I ("route: %s %s:%d -> %s:%d",
                  r->proto == PORTMUX_PROTO_TCP ? "tcp" : "udp",
                  r->listen_addr, r->listen_port, r->target_addr,
                  r->target_port);
        opened++;
    }

    if (opened == 0) {
        PM_LOG_E ("no listeners opened");
        self->run = 0;
        if (self->event_fds[1] >= 0) {
            char b = 0;
            if (write (self->event_fds[1], &b, 1) < 0) { /* ignore */ }
        }
    }
    self->opened = opened;
}

int
portmux_run (Portmux *self)
{
    HevTask *boot;

    if (!self)
        return -1;

    if (hev_task_system_init () < 0) {
        PM_LOG_E ("task system init failed");
        return -1;
    }

    signal (SIGPIPE, SIG_IGN);

    if (socketpair (AF_UNIX, SOCK_STREAM, 0, self->event_fds) < 0) {
        hev_task_system_fini ();
        return -1;
    }
    /* event_fds[0] is polled cooperatively; it must be non-blocking so the
       task yields instead of blocking the whole scheduler thread. */
    {
        int fl = fcntl (self->event_fds[0], F_GETFL, 0);
        fcntl (self->event_fds[0], F_SETFL, fl | O_NONBLOCK);
    }

    self->run = 1;
    self->opened = 0;

    boot = hev_task_new (-1);
    if (!boot) {
        hev_task_system_fini ();
        return -1;
    }
    hev_task_run (boot, bootstrap_task_entry, self);

    hev_task_system_run ();

    if (self->event_fds[0] >= 0) close (self->event_fds[0]);
    if (self->event_fds[1] >= 0) close (self->event_fds[1]);
    self->event_fds[0] = self->event_fds[1] = -1;

    hev_task_system_fini ();

    return self->opened > 0 ? 0 : -1;
}

void
portmux_stop (Portmux *self)
{
    char b = 1;
    if (!self || self->event_fds[1] < 0)
        return;
    if (write (self->event_fds[1], &b, 1) < 0) { /* ignore */ }
}

void
portmux_destroy (Portmux *self)
{
    if (!self)
        return;
    free (self);
}
