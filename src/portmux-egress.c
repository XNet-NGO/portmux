/*
 ============================================================================
 Name        : portmux-egress.c
 Description : Apply egress policy to an upstream socket fd.
 ============================================================================
 */

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "portmux-egress.h"
#include "portmux-log.h"

static int
bind_source_ip (int fd, int family, const char *source_ip)
{
    if (family == AF_INET) {
        struct sockaddr_in sa = { 0 };
        sa.sin_family = AF_INET;
        if (inet_pton (AF_INET, source_ip, &sa.sin_addr) != 1) {
            PM_LOG_W ("egress: bad source ipv4 '%s'", source_ip);
            return -1;
        }
        if (bind (fd, (struct sockaddr *)&sa, sizeof (sa)) < 0) {
            PM_LOG_W ("egress: bind source ipv4 '%s': %s", source_ip,
                      strerror (errno));
            return -1;
        }
    } else {
        struct sockaddr_in6 sa = { 0 };
        sa.sin6_family = AF_INET6;
        if (inet_pton (AF_INET6, source_ip, &sa.sin6_addr) != 1) {
            PM_LOG_W ("egress: bad source ipv6 '%s'", source_ip);
            return -1;
        }
        if (bind (fd, (struct sockaddr *)&sa, sizeof (sa)) < 0) {
            PM_LOG_W ("egress: bind source ipv6 '%s': %s", source_ip,
                      strerror (errno));
            return -1;
        }
    }
    return 0;
}

int
portmux_egress_apply (int fd, int family, const PortmuxEgress *egress)
{
    if (!egress || egress->kind == PORTMUX_EGRESS_NONE)
        return 0;

    switch (egress->kind) {
    case PORTMUX_EGRESS_DEVICE:
#if defined(SO_BINDTODEVICE)
        if (!egress->device)
            return -1;
        if (setsockopt (fd, SOL_SOCKET, SO_BINDTODEVICE, egress->device,
                        strlen (egress->device)) < 0) {
            PM_LOG_W ("egress: SO_BINDTODEVICE '%s': %s", egress->device,
                      strerror (errno));
            return -1;
        }
        return 0;
#else
        PM_LOG_W ("egress: SO_BINDTODEVICE unsupported on this platform");
        return -1;
#endif

    case PORTMUX_EGRESS_SOURCE:
        if (!egress->source_ip)
            return -1;
        return bind_source_ip (fd, family, egress->source_ip);

    case PORTMUX_EGRESS_CALLBACK:
        if (!egress->callback)
            return 0;
        return egress->callback (fd, egress->callback_data);

    case PORTMUX_EGRESS_PROVIDED_FD:
        /* The fd was supplied already-configured by the provider; portmux
           must not re-apply any egress sockopt. Adoption happens at socket
           creation time (see portmux_egress_provide_fd). */
        return 0;

    default:
        return 0;
    }
}

int
portmux_egress_provide_fd (int family, int socktype,
                           const PortmuxEgress *egress)
{
    (void)family; (void)socktype;
    if (!egress || egress->kind != PORTMUX_EGRESS_PROVIDED_FD
        || !egress->provider) {
        PM_LOG_W ("egress: PROVIDED_FD without a provider");
        return -1;
    }
    int fd = egress->provider (family, socktype, egress->callback_data);
    if (fd < 0)
        PM_LOG_W ("egress: provider returned no fd (%d)", fd);
    return fd;
}
