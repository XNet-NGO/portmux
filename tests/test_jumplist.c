/*
 ============================================================================
 Name        : test_jumplist.c
 Description : Unit tests for the multi-hop OPENJ jump-list codec
               (pm_jumplist_encode / _decode / _pop). Pure, no sockets.
 ============================================================================
 */

#include <stdio.h>
#include <string.h>

#include "portmux.h"
#include "portmux-tunnel.h"

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf ("  FAIL: %s\n", (msg)); failures++; } \
} while (0)

static void
mk (PmJumpEndpoint *e, const char *a, int p)
{
    memset (e, 0, sizeof *e);
    snprintf (e->addr, sizeof e->addr, "%s", a);
    e->port = p;
}

static int
ep_eq (const PmJumpEndpoint *a, const PmJumpEndpoint *b)
{
    return a->port == b->port && strcmp (a->addr, b->addr) == 0;
}

int
main (void)
{
    unsigned char buf[1024];

    /* 1. round-trip: 2 hops + target, TCP */
    {
        PmJumpList jl; memset (&jl, 0, sizeof jl);
        jl.proto = PM_MUX_PROTO_TCP;
        jl.nhops = 2;
        mk (&jl.hops[0], "10.0.0.1", 2222);
        mk (&jl.hops[1], "peerC.internal", 2222);
        mk (&jl.target, "127.0.0.1", 5555);

        int n = pm_jumplist_encode (&jl, buf, sizeof buf);
        CHECK (n > 0, "encode 2-hop should succeed");

        PmJumpList out; 
        CHECK (pm_jumplist_decode (buf, (size_t)n, &out) == 0, "decode 2-hop should succeed");
        CHECK (out.proto == PM_MUX_PROTO_TCP, "proto preserved");
        CHECK (out.nhops == 2, "nhops preserved");
        CHECK (ep_eq (&out.hops[0], &jl.hops[0]), "hop0 preserved");
        CHECK (ep_eq (&out.hops[1], &jl.hops[1]), "hop1 preserved");
        CHECK (ep_eq (&out.target, &jl.target), "target preserved");
    }

    /* 2. round-trip: 0 hops (terminal), UDP final */
    {
        PmJumpList jl; memset (&jl, 0, sizeof jl);
        jl.proto = PM_MUX_PROTO_UDP;
        jl.nhops = 0;
        mk (&jl.target, "::1", 53);
        int n = pm_jumplist_encode (&jl, buf, sizeof buf);
        CHECK (n > 0, "encode 0-hop should succeed");
        PmJumpList out;
        CHECK (pm_jumplist_decode (buf, (size_t)n, &out) == 0, "decode 0-hop should succeed");
        CHECK (out.nhops == 0, "0 nhops preserved");
        CHECK (out.proto == PM_MUX_PROTO_UDP, "udp proto preserved");
        CHECK (ep_eq (&out.target, &jl.target), "ipv6 target preserved");
    }

    /* 3. pop: [A,B,target] -> next=A, remainder [B,target] */
    {
        PmJumpList jl; memset (&jl, 0, sizeof jl);
        jl.proto = PM_MUX_PROTO_TCP; jl.nhops = 2;
        mk (&jl.hops[0], "A", 2222);
        mk (&jl.hops[1], "B", 2222);
        mk (&jl.target, "T", 5555);

        PmJumpList rem; PmJumpEndpoint next;
        CHECK (pm_jumplist_pop (&jl, &rem, &next) == 0, "pop should succeed");
        CHECK (strcmp (next.addr, "A") == 0 && next.port == 2222, "popped A");
        CHECK (rem.nhops == 1, "remainder has 1 hop");
        CHECK (strcmp (rem.hops[0].addr, "B") == 0, "remainder hop0 == B");
        CHECK (ep_eq (&rem.target, &jl.target), "remainder target preserved");

        /* pop again -> next=B, remainder 0-hop terminal */
        PmJumpList rem2; PmJumpEndpoint next2;
        CHECK (pm_jumplist_pop (&rem, &rem2, &next2) == 0, "second pop ok");
        CHECK (strcmp (next2.addr, "B") == 0, "popped B");
        CHECK (rem2.nhops == 0, "now terminal (0 hops)");

        /* pop on terminal must fail */
        PmJumpList rem3;
        CHECK (pm_jumplist_pop (&rem2, &rem3, NULL) == -1, "pop on 0-hop must fail");
    }

    /* 4. bounds: too many hops rejected by encode */
    {
        PmJumpList jl; memset (&jl, 0, sizeof jl);
        jl.proto = PM_MUX_PROTO_TCP;
        jl.nhops = PM_MUX_MAX_HOPS + 1;
        mk (&jl.target, "T", 1);
        CHECK (pm_jumplist_encode (&jl, buf, sizeof buf) == -1, "nhops>MAX rejected");
    }

    /* 5. bounds: encode into too-small buffer fails cleanly */
    {
        PmJumpList jl; memset (&jl, 0, sizeof jl);
        jl.proto = PM_MUX_PROTO_TCP; jl.nhops = 1;
        mk (&jl.hops[0], "10.0.0.1", 2222);
        mk (&jl.target, "127.0.0.1", 5555);
        CHECK (pm_jumplist_encode (&jl, buf, 4) == -1, "tiny buffer rejected");
    }

    /* 6. malformed decode: truncated input */
    {
        PmJumpList jl; memset (&jl, 0, sizeof jl);
        jl.proto = PM_MUX_PROTO_TCP; jl.nhops = 1;
        mk (&jl.hops[0], "10.0.0.1", 2222);
        mk (&jl.target, "127.0.0.1", 5555);
        int n = pm_jumplist_encode (&jl, buf, sizeof buf);
        CHECK (n > 5, "encode ok for truncation test");
        CHECK (pm_jumplist_decode (buf, (size_t)n - 1, &jl) == -1, "truncated decode rejected");
        CHECK (pm_jumplist_decode (buf, 1, &jl) == -1, "1-byte decode rejected");
    }

    /* 7. malformed decode: trailing garbage rejected */
    {
        PmJumpList jl; memset (&jl, 0, sizeof jl);
        jl.proto = PM_MUX_PROTO_TCP; jl.nhops = 0;
        mk (&jl.target, "T", 1);
        int n = pm_jumplist_encode (&jl, buf, sizeof buf);
        CHECK (n > 0, "encode 0-hop ok");
        buf[n] = 0xff;                       /* append junk */
        CHECK (pm_jumplist_decode (buf, (size_t)n + 1, &jl) == -1, "trailing garbage rejected");
    }

    /* 8. malformed decode: bad proto byte rejected */
    {
        unsigned char bad[] = { 0x7f, 0x00, 0x01, 'T', 0x00, 0x01 };
        PmJumpList jl;
        CHECK (pm_jumplist_decode (bad, sizeof bad, &jl) == -1, "bad proto rejected");
    }

    if (failures) { printf ("JUMPLIST FAIL: %d\n", failures); printf ("RESULT: %d failure(s)\n", failures); return 1; }
    printf ("JUMPLIST OK: codec round-trip, pop, bounds, malformed all pass\n");
    printf ("RESULT: all passed\n");
    return 0;
}
