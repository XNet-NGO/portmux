/*
 ============================================================================
 Name        : portmux-addr.h
 Description : Address resolution helper.
 ============================================================================
 */

#ifndef __PORTMUX_ADDR_H__
#define __PORTMUX_ADDR_H__

#include <sys/socket.h>

/**
 * portmux_resolve:
 * @host: host string (numeric IPv4/IPv6 or hostname)
 * @port: port number
 * @socktype: SOCK_STREAM or SOCK_DGRAM
 * @passive: non-zero for a bind/listen address (AI_PASSIVE)
 * @out: filled sockaddr storage
 * @out_len: filled length
 *
 * Returns the address family (AF_INET/AF_INET6) on success, < 0 on failure.
 */
int portmux_resolve (const char *host, int port, int socktype, int passive,
                     struct sockaddr_storage *out, socklen_t *out_len);

#endif /* __PORTMUX_ADDR_H__ */
