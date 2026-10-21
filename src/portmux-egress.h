/*
 ============================================================================
 Name        : portmux-egress.h
 Description : Apply egress policy to an upstream socket fd.
 ============================================================================
 */

#ifndef __PORTMUX_EGRESS_H__
#define __PORTMUX_EGRESS_H__

#include "portmux.h"

/**
 * portmux_egress_apply:
 * @fd: a freshly created socket fd (before connect/sendto)
 * @family: AF_INET or AF_INET6 of the fd
 * @egress: policy (may be NULL -> treated as NONE)
 *
 * Returns 0 on success, < 0 on failure (caller should close fd and abort).
 */
int portmux_egress_apply (int fd, int family, const PortmuxEgress *egress);

#endif /* __PORTMUX_EGRESS_H__ */
