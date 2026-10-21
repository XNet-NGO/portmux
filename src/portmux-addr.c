/*
 ============================================================================
 Name        : portmux-addr.c
 Description : Address resolution helper.
 ============================================================================
 */

#include <stdio.h>
#include <string.h>
#include <netdb.h>

#include "portmux-addr.h"
#include "portmux-log.h"

int
portmux_resolve (const char *host, int port, int socktype, int passive,
                 struct sockaddr_storage *out, socklen_t *out_len)
{
    struct addrinfo hints = { 0 };
    struct addrinfo *res = NULL;
    char portstr[16];
    int rc;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;
    if (passive)
        hints.ai_flags = AI_PASSIVE;

    snprintf (portstr, sizeof (portstr), "%d", port);

    rc = getaddrinfo (host, portstr, &hints, &res);
    if (rc != 0 || !res) {
        PM_LOG_W ("resolve '%s':%d: %s", host ? host : "*", port,
                  gai_strerror (rc));
        return -1;
    }

    /* Prefer the first result; getaddrinfo already orders sensibly. */
    memcpy (out, res->ai_addr, res->ai_addrlen);
    *out_len = res->ai_addrlen;
    rc = res->ai_family;

    freeaddrinfo (res);
    return rc;
}
