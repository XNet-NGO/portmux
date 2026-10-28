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

#ifndef PORTMUX_VERSION
#define PORTMUX_VERSION "dev"
#endif

extern int portmux_log_level;

static Portmux *g_pm;

static void
print_version (void)
{
    printf ("portmux %s\n", PORTMUX_VERSION);
}

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
usage (FILE *out, const char *argv0)
{
    fprintf (out,
        "portmux %s — userspace TCP/UDP forwarder, SOCKS5 proxy, and encrypted\n"
        "          (NoisePSK_NN) tunnel with multi-hop jump routing. No TUN, no root.\n"
        "\n"
        "usage: %s [-v] ROUTE [ROUTE ...]\n"
        "       %s <tunnel-server|tunnel-client|tunnel-peer> ...\n"
        "       %s completion <bash|zsh|fish>\n"
        "       %s --help | --help-all | --version\n"
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
        "  %s tunnel-client SERVER_IP:7000 127.0.0.1:5555 ~/.ssh/xnet-tunnel.psk\n"
        "\n"
        "multi-hop jump routing (source-routed, hop-by-hop Noise, one PSK):\n"
        "  %s tunnel-peer LISTEN_ADDR:LISTEN_PORT PSKFILE [CIPHER]\n"
        "    a relay peer: forwards OPENJ to the next hop, or connects the final\n"
        "    target when terminal. PM_EGRESS=dev=IFNAME|src=IP pins next-hop dials.\n"
        "  # edge: accept adb locally (PM_RLISTEN), route via peerB then peerC to target\n"
        "  PM_RLISTEN=127.0.0.1:5555 PM_JUMPS=peerC:2222 \\\n"
        "    %s tunnel-client peerB:2222 TARGET_IP:5555 ~/.ssh/xnet-tunnel.psk\n"
        "    (jump-list = [peerB(carrier), peerC], final target TARGET_IP:5555)\n"
        "\n"
        "Run `%s --help-all` for the full reference (env vars, ciphers, PSK, exit codes).\n",
        PORTMUX_VERSION,
        argv0, argv0, argv0, argv0,
        argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0);
}

/* Expanded reference: every subcommand, all env vars, ciphers, PSK formats,
   egress forms, and exit codes. Printed by --help-all. */
static void
help_all (FILE *out, const char *argv0)
{
    usage (out, argv0);
    fprintf (out,
        "\n"
        "─────────────────────────────── full reference ───────────────────────────────\n"
        "\n"
        "SUBCOMMANDS\n"
        "  (plain routes)         one or more ROUTE/socks args; forward or proxy.\n"
        "  tunnel-server A:P [BRIDGE] PSKFILE [CIPHER]\n"
        "                         accept encrypted carriers on A:P. Single-port form\n"
        "                         (no BRIDGE) = B1 peek-demux: the one port is BOTH the\n"
        "                         carrier dial-in AND the plaintext endpoint.\n"
        "  tunnel-client S:P T:P PSKFILE [CIPHER]\n"
        "                         dial server S:P, splice to local target T:P.\n"
        "  tunnel-peer  A:P PSKFILE [CIPHER]\n"
        "                         relay node for multi-hop jumps (single-port).\n"
        "  completion   bash|zsh|fish      emit a shell completion script to stdout.\n"
        "\n"
        "GLOBAL FLAGS\n"
        "  -v                     verbose logging (info level).\n"
        "  -h, --help             short usage.\n"
        "  --help-all             this full reference.\n"
        "  --version, -V          print version and exit.\n"
        "\n"
        "ENVIRONMENT VARIABLES\n"
        "  PM_RTARGET=ADDR:PORT   tunnel-server: reverse target. On a client-originated\n"
        "                         reverse stream the server connects here (ssh -R style).\n"
        "  PM_RLISTEN=[tcp:|udp:|both:]ADDR:PORT\n"
        "                         tunnel-client: open a local reverse listener. With a\n"
        "                         proto prefix, bind TCP, UDP, or BOTH on that port.\n"
        "                         Also the local plaintext entry for a jump edge.\n"
        "  PM_JUMPS=ADDR:PORT[,ADDR:PORT...]\n"
        "                         tunnel-client: make this the multi-hop EDGE. The\n"
        "                         carrier dials SERVER_ADDR:PORT (= first hop); OPENJ\n"
        "                         carries the remaining hops + the TARGET positional as\n"
        "                         the final destination. Requires PM_RLISTEN. Max %d hops.\n"
        "  PM_EGRESS=dev=IFNAME | src=IP\n"
        "                         tunnel-peer: pin the onward (next-hop) dial's egress.\n"
        "\n"
        "CIPHERS (Noise suite NoisePSK_NN_25519_<CIPHER>_BLAKE2s)\n"
        "  aesgcm   (default)     AES-256-GCM — HW-accelerated on ARMv8 / x86 AES-NI.\n"
        "  chacha                 ChaCha20-Poly1305 — fast without AES hardware.\n"
        "  Both ends of a tunnel MUST use the same cipher.\n"
        "\n"
        "PSK (pre-shared key, the sole authenticator — IP + key, no certificates)\n"
        "  PSKFILE holds either 32 raw bytes OR 64 hex chars (an optional 0x prefix and\n"
        "  trailing newline are tolerated). A mismatched PSK fails the handshake; no\n"
        "  data flows. Keep it 0600.\n"
        "\n"
        "EGRESS (per-route outbound pinning, where supported)\n"
        "  dev=IFNAME             SO_BINDTODEVICE to an interface (needs CAP_NET_RAW).\n"
        "  src=IP                 bind the upstream socket to a local source IP.\n"
        "\n"
        "EXIT CODES\n"
        "  0  clean shutdown (SIGINT/SIGTERM) or help/version.\n"
        "  1  usage error, bad route/PSK, or engine failure.\n"
        "\n"
        "Docs & source: https://github.com/XNet-NGO/portmux\n",
        PM_MUX_MAX_HOPS);
}

/* Emit a shell completion script for bash|zsh|fish to stdout. */
static int
completion (const char *shell)
{
    static const char *subs = "tcp udp socks tunnel-server tunnel-client tunnel-peer completion";
    static const char *flags = "-v -h --help --help-all --version -V";
    if (strcmp (shell, "bash") == 0) {
        printf (
            "# portmux bash completion.  Install:\n"
            "#   portmux completion bash | sudo tee /etc/bash_completion.d/portmux >/dev/null\n"
            "_portmux() {\n"
            "    local cur prev\n"
            "    cur=\"${COMP_WORDS[COMP_CWORD]}\"\n"
            "    prev=\"${COMP_WORDS[COMP_CWORD-1]}\"\n"
            "    if [ \"$prev\" = completion ]; then\n"
            "        COMPREPLY=( $(compgen -W 'bash zsh fish' -- \"$cur\") ); return\n"
            "    fi\n"
            "    case \"$cur\" in\n"
            "        -*) COMPREPLY=( $(compgen -W '%s' -- \"$cur\") ); return;;\n"
            "    esac\n"
            "    if [ \"$COMP_CWORD\" -eq 1 ]; then\n"
            "        COMPREPLY=( $(compgen -W '%s %s' -- \"$cur\") )\n"
            "    fi\n"
            "}\n"
            "complete -o default -F _portmux portmux\n",
            flags, subs, flags);
        return 0;
    }
    if (strcmp (shell, "zsh") == 0) {
        printf (
            "#compdef portmux\n"
            "# portmux zsh completion.  Install: put this on your $fpath as _portmux\n"
            "#   portmux completion zsh > \"${fpath[1]}/_portmux\"\n"
            "_portmux() {\n"
            "  local -a subs flags\n"
            "  subs=(tcp udp socks tunnel-server tunnel-client tunnel-peer completion)\n"
            "  flags=(-v -h --help --help-all --version -V)\n"
            "  if (( CURRENT == 2 )); then\n"
            "    _describe 'command' subs; _describe 'flag' flags\n"
            "  elif [[ \"${words[CURRENT-1]}\" == completion ]]; then\n"
            "    compadd bash zsh fish\n"
            "  fi\n"
            "}\n"
            "_portmux \"$@\"\n");
        return 0;
    }
    if (strcmp (shell, "fish") == 0) {
        printf (
            "# portmux fish completion.  Install:\n"
            "#   portmux completion fish > ~/.config/fish/completions/portmux.fish\n"
            "complete -c portmux -f\n"
            "for s in tcp udp socks tunnel-server tunnel-client tunnel-peer completion\n"
            "    complete -c portmux -n '__fish_use_subcommand' -a $s\n"
            "end\n"
            "complete -c portmux -s v -d 'verbose logging'\n"
            "complete -c portmux -s h -l help -d 'short usage'\n"
            "complete -c portmux -l help-all -d 'full reference'\n"
            "complete -c portmux -l version -s V -d 'print version'\n"
            "complete -c portmux -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'\n");
        return 0;
    }
    fprintf (stderr, "completion: unknown shell '%s' (want bash|zsh|fish)\n", shell);
    return 1;
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

    /* Global flags / meta subcommands handled before route parsing. These may
       appear as the first arg (argv[1]); --help/--version print to stdout and
       exit 0. */
    if (argc >= 2) {
        const char *a = argv[1];
        if (strcmp (a, "--help") == 0 || strcmp (a, "-h") == 0) {
            usage (stdout, argv[0]); return 0;
        }
        if (strcmp (a, "--help-all") == 0) {
            help_all (stdout, argv[0]); return 0;
        }
        if (strcmp (a, "--version") == 0 || strcmp (a, "-V") == 0) {
            print_version (); return 0;
        }
        if (strcmp (a, "completion") == 0) {
            if (argc < 3) { fprintf (stderr, "completion: need a shell (bash|zsh|fish)\n"); return 1; }
            return completion (argv[2]);
        }
    }

    if (argc < 2) {
        usage (stderr, argv[0]);
        return 1;
    }

    if (strcmp (argv[1], "-v") == 0) {
        portmux_log_level = 4;
        first = 2;
    }

    if (first >= argc) {
        usage (stderr, argv[0]);
        return 1;
    }

    /* Tunnel subcommand: tunnel-peer (multi-hop relay). Single-port peek-demux
     * listener that relays OPENJ to the next hop (or connects the final target
     * when it is the terminal hop). Shares the chain PSK.
     *     tunnel-peer LISTEN_ADDR:PORT PSKFILE [CIPHER]
     * Optional egress for next-hop dials: PM_EGRESS=dev=IFNAME | src=IP. */
    if (strcmp (argv[first], "tunnel-peer") == 0) {
        if (argc - first < 3) { usage (stderr, argv[0]); return 1; }
        char a1[256]; snprintf (a1, sizeof a1, "%s", argv[first + 1]);
        char *c1 = strrchr (a1, ':');
        if (!c1) { fprintf (stderr, "expected ADDR:PORT\n"); return 1; }
        *c1 = '\0';
        const char *addr1 = a1; int port1 = atoi (c1 + 1);
        const char *pskfile = argv[first + 2];
        PmTunnelCipher cipher = parse_cipher (argc - first >= 4 ? argv[first + 3] : NULL);

        unsigned char psk[PM_TUNNEL_PSK_LEN];
        if (load_psk (pskfile, psk) < 0) return 1;

        PortmuxEgress eg = { 0 }; PortmuxEgress *egp = NULL;
        const char *es = getenv ("PM_EGRESS");
        if (es && strncmp (es, "dev=", 4) == 0) { eg.kind = PORTMUX_EGRESS_DEVICE; eg.device = es + 4; egp = &eg; }
        else if (es && strncmp (es, "src=", 4) == 0) { eg.kind = PORTMUX_EGRESS_SOURCE; eg.source_ip = es + 4; egp = &eg; }

        g_pm = portmux_new ();
        if (!g_pm) { fprintf (stderr, "portmux_new failed\n"); return 1; }
        int rc = portmux_add_tunnel_peer (g_pm, addr1, port1, psk, cipher, egp);
        memset (psk, 0, sizeof psk);
        if (rc < 0) { fprintf (stderr, "tunnel-peer setup failed\n"); portmux_destroy (g_pm); return 1; }
        signal (SIGINT, on_signal); signal (SIGTERM, on_signal);
        rc = portmux_run (g_pm);
        portmux_destroy (g_pm);
        return rc == 0 ? 0 : 1;
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
        if (argc - first < need) { usage (stderr, argv[0]); return 1; }

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

            /* EDGE multi-hop jump: PM_JUMPS=peerB:port,peerC:port makes this
               client the chain entry. Its reverse listener (PM_RLISTEN) accepts
               local plaintext clients and emits OPENJ. The jump-list is
               [carrier(SERVER_ADDR:PORT), PM_JUMPS...] and the final target is
               the TARGET_ADDR:TARGET_PORT positional. Requires PM_RLISTEN. */
            const char *jumps = getenv ("PM_JUMPS");
            if (rc == 0 && jumps && *jumps) {
                if (rl_port <= 0) {
                    fprintf (stderr, "PM_JUMPS requires PM_RLISTEN=addr:port (the edge's local listener)\n");
                    portmux_destroy (g_pm); return 1;
                }
                PmJumpEndpoint hops[PM_MUX_MAX_HOPS];
                memset (hops, 0, sizeof hops);
                int nh = 0;
                /* hop[0] = the carrier destination (this client's SERVER) */
                if (strlen (addr1) >= PM_MUX_ADDR_MAX) { fprintf (stderr, "carrier addr too long\n"); portmux_destroy (g_pm); return 1; }
                snprintf (hops[nh].addr, sizeof hops[nh].addr, "%s", addr1);
                hops[nh].port = port1; nh++;
                /* append PM_JUMPS peers */
                char jb[1024]; snprintf (jb, sizeof jb, "%s", jumps);
                char *save = NULL, *tok = strtok_r (jb, ",", &save);
                while (tok && nh < PM_MUX_MAX_HOPS) {
                    char *cc = strrchr (tok, ':');
                    if (!cc) { fprintf (stderr, "PM_JUMPS entry needs addr:port: %s\n", tok); portmux_destroy (g_pm); return 1; }
                    *cc = '\0';
                    if (strlen (tok) >= PM_MUX_ADDR_MAX) { fprintf (stderr, "PM_JUMPS addr too long: %s\n", tok); portmux_destroy (g_pm); return 1; }
                    snprintf (hops[nh].addr, sizeof hops[nh].addr, "%s", tok);
                    hops[nh].port = atoi (cc + 1); nh++;
                    tok = strtok_r (NULL, ",", &save);
                }
                if (tok) { fprintf (stderr, "PM_JUMPS: too many hops (max %d)\n", PM_MUX_MAX_HOPS); portmux_destroy (g_pm); return 1; }
                /* final target = the TARGET positional (addr2:port2) */
                if (!addr2 || port2 <= 0) { fprintf (stderr, "PM_JUMPS needs a TARGET_ADDR:TARGET_PORT positional\n"); portmux_destroy (g_pm); return 1; }
                if (portmux_tunnel_set_jumps (g_pm, hops, nh, addr2, port2, PM_MUX_PROTO_TCP) < 0) {
                    fprintf (stderr, "set_jumps failed\n"); portmux_destroy (g_pm); return 1;
                }
                fprintf (stderr, "edge jump: %d hop(s) -> target %s:%d (local listener %s:%d)\n",
                         nh, addr2, port2, rl_addr ? rl_addr : "127.0.0.1", rl_port);
            }
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
