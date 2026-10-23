/*
 ============================================================================
 Name        : portmux-internal.h
 Description : Internal engine structures and helpers shared between the core
               (portmux.c) and the SOCKS5 inbound (portmux-socks.c). NOT part
               of the public API (include/portmux.h).
 ============================================================================
 */

#ifndef __PORTMUX_INTERNAL_H__
#define __PORTMUX_INTERNAL_H__

#include <hev-task.h>

#include "portmux.h"

/* Compile-time limits (mirrored in portmux.c; keep in sync). */
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

/* ── shared helpers (defined in portmux.c) ── */

void pm_task_register (Portmux *self, PmTaskNode *node);
void pm_task_unregister (Portmux *self, PmTaskNode *node);

/* Yielder bound to self->run: returns -1 (abort) once run==0. */
int pm_run_yielder (HevTaskYieldType type, void *data);

/* Disable Nagle on a TCP fd. */
void pm_set_nodelay (int fd);

/* Monotonic milliseconds. */
unsigned long pm_mono_ms (void);

/* Create an upstream socket of (family, socktype) with the route's egress
   policy applied (SOURCE/DEVICE/CALLBACK) or adopted (PROVIDED_FD). Returns a
   fd >= 0 (ownership to caller) or < 0. The fd is NOT yet connected. */
int pm_make_upstream_fd (PortmuxRoute *r, int family, int socktype);

/* The SOCKS5 listener task entry (portmux-socks.c). Spawned per SOCKS route. */
void pm_socks_listen_task (void *data);

/* ── tunnel (portmux-tunnel.c) ── */
/* Register a tunnel route, stashing the opaque PmTunnelCfg* on the route and
   marking it as a tunnel client (is_server=0) or server (is_server=1). Returns
   0 on success. Defined in portmux-tunnel.c (uses the public route array). */
int pm_register_tunnel_route (Portmux *self, void *cfg, int is_server);
/* Bootstrap-dispatched task entries. */
void pm_tunnel_server_entry (void *route);
void pm_tunnel_client_entry (void *route);
/* Open a tunnel server's listeners before spawning its task. Returns 0/-1. */
int pm_tunnel_open_server (PortmuxRoute *route);

#endif /* __PORTMUX_INTERNAL_H__ */
