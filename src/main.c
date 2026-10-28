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
#include "portmux-tunnel.h"

extern int portmux_log_level;

static Portmux *g_pm;

static void
on_signal (int sig)
{
    (void)sig;
    if (g_pm)
        portmux_stop (g_pm);
}

/* Load a 32-byte PSK. The file may be raw 32 bytes or 64 hex chars (optionally
   with a trailing newline / "0x" prefix). Returns 0 on success. */
static int
load_psk (const char *path, unsigned char out[PM_TUNNEL_PSK_LEN])
{
    FILE *f = fopen (path, "rb");
    if (!f) {
        fprintf (stderr, "psk: cannot open %s\n", path);
        return -1;
    }
    unsigned char buf[256];
    size_t n = fread (buf, 1, sizeof buf, f);
    fclose (f);

    /* strip trailing whitespace */
    while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == ' '))
        n--;

    if (n == PM_TUNNEL_PSK_LEN) {            /* raw 32 bytes */
        memcpy (out, buf, PM_TUNNEL_PSK_LEN);
        return 0;
    }
    /* hex: allow optional 0x prefix */
    size_t off = (n >= 2 && buf[0] == '0' && (buf[1] == 'x' || buf[1] == 'X')) ? 2 : 0;
    if (n - off == PM_TUNNEL_PSK_LEN * 2) {
        for (int i = 0; i < PM_TUNNEL_PSK_LEN; i++) {
            unsigned v;
            if (sscanf ((const char *)buf + off + i * 2, "%2x", &v) != 1)
                return -1;
            out[i] = (unsigned char)v;
        }
        return 0;
    }
    fprintf (stderr, "psk: %s must be 32 raw bytes or 64 hex chars (got %zu)\n",
             path, n);
    return -1;
}

static PmTunnelCipher
parse_cipher (const char *s)
{
    if (s && (strcmp (s, "chacha") == 0 || strcmp (s, "chachapoly") == 0))
        return PM_TUNNEL_CIPHER_CHACHAPOLY;
    return PM_TUNNEL_CIPHER_AESGCM; /* default: HW-accelerated on ARMv8 */
}


static void
usage (const char *argv0)
{
    fprintf (stderr,
        "usage: %s [-v] ROUTE [ROUTE ...]\n"
        "\n"
        "ROUTE: PROTO:LADDR:LPORT:TADDR:TPORT[:EGRESS]\n"
        "       socks:LADDR:LPORT[:EGRESS]     (SOCKS5 proxy, dynamic target)\n"
        "  PROTO  tcp | udp\n"
        "  LADDR  listen address (use 0.0.0.0 / :: for any; [::1] for v6 lit)\n"
        "  EGRESS (optional) dev=IFNAME | src=IP\n"
        "\n"
        "examples:\n"
        "  # MCP server :39811 -> reverse-ssh local forward :2222 (loopback)\n"
        "  %s tcp:127.0.0.1:39811:127.0.0.1:2222\n"
        "  # DAW -> VST app, udp, pin egress to wlan0\n"
        "  %s udp:127.0.0.1:9000:127.0.0.1:9001:dev=wlan0\n"
        "  # SOCKS5 proxy on :1080, upstream pinned to wlan0\n"
        "  %s socks:127.0.0.1:1080:dev=wlan0\n"
        "\n"
        "encrypted tunnel (NoisePSK_NN, IP + pre-shared key; no certs):\n"
        "  %s tunnel-server LISTEN_ADDR:LISTEN_PORT BRIDGE_ADDR:BRIDGE_PORT PSKFILE [CIPHER]\n"
        "  %s tunnel-client SERVER_ADDR:SERVER_PORT TARGET_ADDR:TARGET_PORT PSKFILE [CIPHER]\n"
        "    CIPHER  aesgcm (default) | chacha\n"
        "    PSKFILE 32 raw bytes or 64 hex chars (e.g. ~/.ssh/xnet-tunnel.psk)\n"
        "  # on the box: accept clients on :7000, expose adb bridge on :5555\n"
        "  %s tunnel-server 0.0.0.0:7000 127.0.0.1:5555 ~/.ssh/xnet-tunnel.psk\n"
        "  # on the phone: dial the box, splice to local adbd:5555\n"
        "  %s tunnel-client SERVER_IP:7000 127.0.0.1:5555 ~/.ssh/xnet-tunnel.psk\n",
        argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0);
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
        /* socks:LADDR:LPORT[:EGRESS] has 3-4 fields with a dynamic target. */
        if (nf >= 3 && strcmp (fields[0], "socks") == 0) {
            PortmuxEgress eg = { 0 };
            PortmuxEgress *egp = NULL;
            if (nf == 4 && fields[3] && *fields[3]) {
                if (strncmp (fields[3], "dev=", 4) == 0) {
                    eg.kind = PORTMUX_EGRESS_DEVICE;
                    eg.device = fields[3] + 4;
                    egp = &eg;
                } else if (strncmp (fields[3], "src=", 4) == 0) {
                    eg.kind = PORTMUX_EGRESS_SOURCE;
                    eg.source_ip = fields[3] + 4;
                    egp = &eg;
                } else {
                    fprintf (stderr, "bad egress: %s\n", fields[3]);
                    return -1;
                }
            }
            return portmux_add_socks (pm, fields[1], atoi (fields[2]), egp);
        }
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

    /* Tunnel subcommands: tunnel-server / tunnel-client. */
    if (strcmp (argv[first], "tunnel-server") == 0 ||
        strcmp (argv[first], "tunnel-client") == 0) {
        int is_server = (strcmp (argv[first], "tunnel-server") == 0);

        /* Server supports a SINGLE-PORT form (B1 peek-demux, no bridge):
         *     tunnel-server LISTEN_ADDR:PORT PSKFILE [CIPHER]
         * and the legacy two-port form:
         *     tunnel-server LISTEN_ADDR:PORT PUBLIC_ADDR:PORT PSKFILE [CIPHER]
         * The client always takes: tunnel-client SRV:PORT TARGET:PORT PSKFILE [CIPHER].
         * Distinguish by whether the 2nd positional looks like ADDR:PORT. */
        int single_port = 0;
        if (is_server) {
            const char *a2 = (argc - first >= 3) ? argv[first + 2] : NULL;
            /* two-port iff a2 contains ':' AND there is still a PSKFILE after it */
            int a2_is_addr = (a2 && strrchr (a2, ':') != NULL && (argc - first >= 4));
            single_port = !a2_is_addr;
        }

        int need = single_port ? 3 : 4;
        if (argc - first < need) { usage (argv[0]); return 1; }

        char a1[256], a2[256];
        snprintf (a1, sizeof a1, "%s", argv[first + 1]);
        const char *pskfile;
        PmTunnelCipher cipher;
        const char *addr2 = NULL; int port2 = 0;

        char *c1 = strrchr (a1, ':');
        if (!c1) { fprintf (stderr, "expected ADDR:PORT\n"); return 1; }
        *c1 = '\0';
        const char *addr1 = a1; int port1 = atoi (c1 + 1);

        if (single_port) {
            pskfile = argv[first + 2];
            cipher = parse_cipher (argc - first >= 4 ? argv[first + 3] : NULL);
            /* single-port: no separate public listener (port2 = 0) */
        } else {
            snprintf (a2, sizeof a2, "%s", argv[first + 2]);
            pskfile = argv[first + 3];
            cipher = parse_cipher (argc - first >= 5 ? argv[first + 4] : NULL);
            char *c2 = strrchr (a2, ':');
            if (!c2) { fprintf (stderr, "expected ADDR:PORT\n"); return 1; }
            *c2 = '\0';
            addr2 = a2; port2 = atoi (c2 + 1);
        }

        unsigned char psk[PM_TUNNEL_PSK_LEN];
        if (load_psk (pskfile, psk) < 0)
            return 1;

        g_pm = portmux_new ();
        if (!g_pm) { fprintf (stderr, "portmux_new failed\n"); return 1; }

        int rc;
        if (is_server) {
            rc = portmux_add_tunnel_server (g_pm, addr1, port1,
                                            addr2 ? addr2 : "127.0.0.1", port2,
                                            psk, cipher);
            /* reverse target (server end of an ssh -R style reverse stream):
               PM_RTARGET=addr:port -> server connects here on a reverse OPEN */
            const char *rt = getenv ("PM_RTARGET");
            if (rc == 0 && rt && strrchr (rt, ':')) {
                char buf[256]; snprintf (buf, sizeof buf, "%s", rt);
                char *c = strrchr (buf, ':'); *c = '\0';
                portmux_tunnel_set_reverse_target (g_pm, buf, atoi (c + 1));
            }
        } else {
            /* reverse listener (client end): PM_RLISTEN=addr:port -> local
               connections there become reverse streams to the server target. */
            const char *rl = getenv ("PM_RLISTEN");
            const char *rl_addr = NULL; int rl_port = 0; int rl_proto = 0;
            char buf[256];
            if (rl) {
                /* optional proto prefix: PM_RLISTEN=both:127.0.0.1:5301 */
                if (strncmp (rl, "both:", 5) == 0) { rl_proto = 2; rl += 5; }
                else if (strncmp (rl, "udp:", 4) == 0) { rl_proto = 1; rl += 4; }
                else if (strncmp (rl, "tcp:", 4) == 0) { rl_proto = 0; rl += 4; }
                if (strrchr (rl, ':')) {
                    snprintf (buf, sizeof buf, "%s", rl);
                    char *c = strrchr (buf, ':'); *c = '\0';
                    rl_addr = buf; rl_port = atoi (c + 1);
                }
            }
            rc = portmux_add_tunnel_client (g_pm, rl_addr, rl_port, addr1, port1,
                                            addr2, port2, psk, cipher, NULL);
            if (rc == 0 && rl_port > 0) portmux_tunnel_set_reverse_proto (g_pm, rl_proto);
        }
        /* wipe the local PSK copy from this stack frame */
        memset (psk, 0, sizeof psk);
        if (rc < 0) {
            fprintf (stderr, "tunnel setup failed\n");
            portmux_destroy (g_pm);
            return 1;
        }
        signal (SIGINT, on_signal);
        signal (SIGTERM, on_signal);
        rc = portmux_run (g_pm);
        portmux_destroy (g_pm);
        return rc == 0 ? 0 : 1;
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
