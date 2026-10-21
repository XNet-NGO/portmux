/*
 ============================================================================
 Name        : portmux.h
 Description : Userspace TCP/UDP port forwarder (lwIP-free).
               Agnostic: loopback same-device relays and cross-interface
               relays, with optional egress pinning. Built on hev-task-system
               coroutines for single-thread M:N concurrency.
 License     : MIT (matches vendored hev-task-system)
 ============================================================================
 */

#ifndef __PORTMUX_H__
#define __PORTMUX_H__

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _PortmuxRoute PortmuxRoute;

/**
 * PortmuxProto:
 * Transport protocol for a route.
 */
typedef enum
{
    PORTMUX_PROTO_TCP,
    PORTMUX_PROTO_UDP,
} PortmuxProto;

/**
 * PortmuxEgressKind:
 * How the upstream (target) socket selects its egress path.
 *
 * - NONE:   default routing (loopback / default route). Use for same-device.
 * - DEVICE: bind the socket to a named interface via SO_BINDTODEVICE.
 *           Needs CAP_NET_RAW / root on Android.
 * - SOURCE: bind the socket to a specific local source IP (no privilege).
 * - CALLBACK: invoke a user callback on the raw fd before connect. This is the
 *             Android no-root path: the callback calls Network.bindSocket(fd)
 *             through JNI. Fully agnostic — the core never assumes a policy.
 */
typedef enum
{
    PORTMUX_EGRESS_NONE,
    PORTMUX_EGRESS_DEVICE,
    PORTMUX_EGRESS_SOURCE,
    PORTMUX_EGRESS_CALLBACK,
} PortmuxEgressKind;

/**
 * PortmuxFdHook:
 * @fd: a freshly created, not-yet-connected socket fd.
 * @user_data: opaque pointer from PortmuxEgress.callback_data.
 *
 * Called right after socket() and before connect()/sendto(). Return 0 to
 * proceed, < 0 to abort this connection. Use it to pin the socket to a
 * specific Android Network (Network.bindSocket), set marks, or any sockopt.
 */
typedef int (*PortmuxFdHook) (int fd, void *user_data);

/**
 * PortmuxEgress:
 * Egress policy applied to every upstream socket a route creates.
 */
typedef struct
{
    PortmuxEgressKind kind;
    const char *device;     /* DEVICE: interface name, e.g. "wlan0"          */
    const char *source_ip;  /* SOURCE: local source IP to bind, e.g. "10.0.0.2" */
    PortmuxFdHook callback; /* CALLBACK: fd hook                              */
    void *callback_data;    /* CALLBACK: opaque data for the hook            */
} PortmuxEgress;

typedef struct _Portmux Portmux;

/**
 * portmux_new:
 *
 * Create an empty forwarder instance. Does NOT touch the task system.
 * Returns NULL on failure.
 */
Portmux *portmux_new (void);

/**
 * portmux_add_route:
 * @self: a #Portmux
 * @proto: TCP or UDP
 * @listen_addr: local bind address (e.g. "127.0.0.1", "0.0.0.0", "::")
 * @listen_port: local port to listen on
 * @target_addr: upstream host to forward to
 * @target_port: upstream port
 * @egress: egress policy (may be NULL for PORTMUX_EGRESS_NONE)
 *
 * Register a route. Must be called before portmux_run().
 * Returns 0 on success, < 0 on error.
 */
int portmux_add_route (Portmux *self, PortmuxProto proto,
                       const char *listen_addr, int listen_port,
                       const char *target_addr, int target_port,
                       const PortmuxEgress *egress);

/**
 * portmux_run:
 * @self: a #Portmux
 *
 * Initializes the (per-thread) task system, opens all listeners, and runs the
 * event loop. MUST be called on the thread that will own the forwarder; all
 * task-system state is thread-local. Blocks until portmux_stop().
 * Returns 0 on clean shutdown, < 0 if no listener could be opened.
 */
int portmux_run (Portmux *self);

/**
 * portmux_stop:
 * @self: a #Portmux
 *
 * Signal the running loop to shut down. Safe to call from another thread
 * or a signal handler.
 */
void portmux_stop (Portmux *self);

/**
 * portmux_destroy:
 * @self: a #Portmux
 *
 * Free the instance. Do not call while running.
 */
void portmux_destroy (Portmux *self);

#ifdef __cplusplus
}
#endif

#endif /* __PORTMUX_H__ */
