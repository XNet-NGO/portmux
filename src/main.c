/*
 ============================================================================
 Name        : main.c
 Description : portmux CLI driver.
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "portmux.h"

extern int portmux_log_level;

static Portmux *g_pm;

static void
on_signal (int sig)
{
    (void)sig;
    if (g_pm)
        portmux_stop (g_pm);
}

static void
usage (const char *argv0)
{
    fprintf (stderr,
        "usage: %s [-v] ROUTE [ROUTE ...]\n"
        "\n"
        "ROUTE: PROTO:LADDR:LPORT:TADDR:TPORT[:EGRESS]\n"
        "  PROTO  tcp | udp\n"
        "  LADDR  listen address (use 0.0.0.0 / :: for any; [::1] for v6 lit)\n"
        "  EGRESS (optional) dev=IFNAME | src=IP\n"
        "\n"
        "examples:\n"
        "  # MCP server :39811 -> reverse-ssh local forward :2222 (loopback)\n"
        "  %s tcp:127.0.0.1:39811:127.0.0.1:2222\n"
        "  # DAW -> VST app, udp, pin egress to wlan0\n"
        "  %s udp:127.0.0.1:9000:127.0.0.1:9001:dev=wlan0\n",
        argv0, argv0, argv0);
}

/* Split "a:b:c:d:e[:f]" honoring a single [..] bracketed v6 literal in fields.
   For simplicity we split on ':' but allow bracketed addresses. */
static int
parse_route (char *spec, Portmux *pm)
{
    char *fields[6] = { 0 };
    int nf = 0;
    char *p = spec;

    while (p && *p && nf < 6) {
        char *start;
        if (*p == '[') {
            start = ++p;
            char *end = strchr (p, ']');
            if (!end)
                return -1;
            *end = '\0';
            fields[nf++] = start;
            p = end + 1;
            if (*p == ':')
                p++;
        } else {
            start = p;
            char *colon = strchr (p, ':');
            if (colon) {
                *colon = '\0';
                p = colon + 1;
            } else {
                p = NULL;
            }
            fields[nf++] = start;
        }
    }

    if (nf < 5) {
        fprintf (stderr, "bad route (need 5-6 fields): %s\n", spec);
        return -1;
    }

    PortmuxProto proto;
    if (strcmp (fields[0], "tcp") == 0)
        proto = PORTMUX_PROTO_TCP;
    else if (strcmp (fields[0], "udp") == 0)
        proto = PORTMUX_PROTO_UDP;
    else {
        fprintf (stderr, "bad proto: %s\n", fields[0]);
        return -1;
    }

    PortmuxEgress eg = { 0 };
    PortmuxEgress *egp = NULL;
    if (nf == 6 && fields[5] && *fields[5]) {
        if (strncmp (fields[5], "dev=", 4) == 0) {
            eg.kind = PORTMUX_EGRESS_DEVICE;
            eg.device = fields[5] + 4;
            egp = &eg;
        } else if (strncmp (fields[5], "src=", 4) == 0) {
            eg.kind = PORTMUX_EGRESS_SOURCE;
            eg.source_ip = fields[5] + 4;
            egp = &eg;
        } else {
            fprintf (stderr, "bad egress: %s\n", fields[5]);
            return -1;
        }
    }

    return portmux_add_route (pm, proto, fields[1], atoi (fields[2]),
                              fields[3], atoi (fields[4]), egp);
}

int
main (int argc, char **argv)
{
    int i, first = 1;

    if (argc < 2) {
        usage (argv[0]);
        return 1;
    }

    if (strcmp (argv[1], "-v") == 0) {
        portmux_log_level = 4;
        first = 2;
    }

    if (first >= argc) {
        usage (argv[0]);
        return 1;
    }

    g_pm = portmux_new ();
    if (!g_pm) {
        fprintf (stderr, "portmux_new failed\n");
        return 1;
    }

    for (i = first; i < argc; i++) {
        if (parse_route (argv[i], g_pm) < 0) {
            portmux_destroy (g_pm);
            return 1;
        }
    }

    signal (SIGINT, on_signal);
    signal (SIGTERM, on_signal);

    int rc = portmux_run (g_pm);
    portmux_destroy (g_pm);
    return rc == 0 ? 0 : 1;
}
