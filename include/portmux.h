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
    /* SOCKS5: the listener is a SOCKS5 proxy. The per-connection target is
       supplied by the client in the SOCKS5 request (CONNECT / UDP ASSOCIATE),
       not fixed on the route. Added via portmux_add_socks(). Every upstream
       socket still passes through the route's PortmuxEgress, so egress pinning
       is applied per client connection. */
    PORTMUX_PROTO_SOCKS5,
    /* Encrypted rendezvous tunnel (see portmux-tunnel.h). Registered via
       portmux_add_tunnel_client()/portmux_add_tunnel_server(), not
       portmux_add_route(). */
    PORTMUX_PROTO_TUNNEL_CLIENT,
    PORTMUX_PROTO_TUNNEL_SERVER,
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
    /* PROVIDED_FD: the upstream socket is supplied by a provider callback
       (e.g. a privileged helper daemon that created an interface-pinned or
       low-port-bound socket under CAP_NET_RAW/CAP_NET_BIND_SERVICE and passed
       the fd back via SCM_RIGHTS). portmux adopts the fd AS-IS instead of
       calling socket(); no egress sockopt is applied by portmux. */
    PORTMUX_EGRESS_PROVIDED_FD,
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
 * PortmuxFdProvider:
 * @family: AF_INET or AF_INET6 that the route resolved to.
 * @socktype: SOCK_STREAM or SOCK_DGRAM.
 * @user_data: opaque pointer from PortmuxEgress.callback_data.
 *
 * For PORTMUX_EGRESS_PROVIDED_FD. Must return a ready-to-use, NOT-yet-connected
 * socket fd of the given family/type (ownership transfers to portmux, which
 * will connect() and close() it), or < 0 on failure. Used to adopt a socket
 * minted by a privileged helper (interface-pinned / low-port-bound).
 */
typedef int (*PortmuxFdProvider) (int family, int socktype, void *user_data);

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
    PortmuxFdProvider provider; /* PROVIDED_FD: supplies the upstream fd      */
    void *callback_data;    /* CALLBACK/PROVIDED_FD: opaque data             */
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
 * portmux_add_socks:
 * @self: a #Portmux
 * @listen_addr: local bind address (e.g. "127.0.0.1", "::1")
 * @listen_port: local port to listen on for SOCKS5 clients
 * @egress: egress policy applied to every upstream socket the proxy opens
 *          (may be NULL for PORTMUX_EGRESS_NONE). This is what makes the
 *          proxy's upstream pinnable per connection (e.g. Android
 *          android_setsocknetwork via PORTMUX_EGRESS_CALLBACK), with no root.
 *
 * Register a SOCKS5 proxy listener. Unlike portmux_add_route, there is no fixed
 * target: each accepted client supplies the destination in the SOCKS5 request.
 * Supports no-auth (method 0x00), CONNECT (TCP) and UDP ASSOCIATE. Must be
 * called before portmux_run(). Returns 0 on success, < 0 on error.
 */
int portmux_add_socks (Portmux *self, const char *listen_addr, int listen_port,
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
