/*
 ============================================================================
 Name        : test_relaybind.c
 Description : Unit tests for the reverse-multihop relay binding table
               (pm_relaybind_*), which maps a stream id on one carrier to a
               freshly-allocated stream id on the other carrier so a relay hop
               can carry the FULL symmetric mux (forward AND reverse streams)
               across two carriers with no id collisions. Pure, no sockets.
 ============================================================================
 */

#include <stdio.h>
#include <string.h>

#include "portmux.h"
#include "portmux-tunnel.h"
#include "portmux-relaybind.h"

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf ("  FAIL: %s\n", (msg)); failures++; } \
} while (0)

int
main (void)
{
    PmRelayBindTable t;

    /* 1. fresh table has no bindings */
    pm_relaybind_init (&t);
    CHECK (pm_relaybind_lookup_a (&t, 0x0001) == NULL, "empty: lookup_a miss");
    CHECK (pm_relaybind_lookup_b (&t, 0x0001) == NULL, "empty: lookup_b miss");

    /* 2. add an a->b binding, both directions resolve to the same record */
    {
        PmRelayBind *bnd = pm_relaybind_add (&t, 0x8001 /*a side (reverse)*/,
                                                 0x0005 /*b side (forward)*/);
        CHECK (bnd != NULL, "add returns a record");
        CHECK (bnd->a_id == 0x8001 && bnd->b_id == 0x0005, "ids stored");
        PmRelayBind *la = pm_relaybind_lookup_a (&t, 0x8001);
        PmRelayBind *lb = pm_relaybind_lookup_b (&t, 0x0005);
        CHECK (la == bnd, "lookup_a finds it");
        CHECK (lb == bnd, "lookup_b finds it");
    }

    /* 3. distinct bindings don't collide across directions */
    {
        PmRelayBind *b2 = pm_relaybind_add (&t, 0x0007 /*a fwd*/, 0x8003 /*b rev*/);
        CHECK (b2 != NULL, "second add ok");
        CHECK (pm_relaybind_lookup_a (&t, 0x0007) == b2, "lookup_a #2");
        CHECK (pm_relaybind_lookup_b (&t, 0x8003) == b2, "lookup_b #2");
        /* the first binding is still intact */
        CHECK (pm_relaybind_lookup_a (&t, 0x8001) != NULL, "first binding intact");
        CHECK (pm_relaybind_lookup_a (&t, 0x8001) != b2, "distinct records");
    }

    /* 4. remove by a-id frees both lookups */
    {
        pm_relaybind_del_a (&t, 0x8001);
        CHECK (pm_relaybind_lookup_a (&t, 0x8001) == NULL, "del_a: a miss");
        CHECK (pm_relaybind_lookup_b (&t, 0x0005) == NULL, "del_a: b miss too");
        /* the other binding survives */
        CHECK (pm_relaybind_lookup_a (&t, 0x0007) != NULL, "other survives del");
    }

    /* 5. remove by b-id frees both lookups */
    {
        pm_relaybind_del_b (&t, 0x8003);
        CHECK (pm_relaybind_lookup_a (&t, 0x0007) == NULL, "del_b: a miss");
        CHECK (pm_relaybind_lookup_b (&t, 0x8003) == NULL, "del_b: b miss");
    }

    /* 6. id allocator: forward + reverse pools, never 0 / 0x8000, no reuse of
          a live slot. */
    {
        PmRelayBindTable t2;
        pm_relaybind_init (&t2);
        unsigned int f1 = pm_relaybind_alloc (&t2, 0 /*forward*/);
        unsigned int f2 = pm_relaybind_alloc (&t2, 0 /*forward*/);
        unsigned int r1 = pm_relaybind_alloc (&t2, 1 /*reverse*/);
        CHECK (f1 != 0 && (f1 & PM_MUX_ORIGIN) == 0, "forward id non-zero, origin clear");
        CHECK (f2 != 0 && f2 != f1, "forward ids distinct");
        CHECK (r1 != 0 && (r1 & PM_MUX_ORIGIN) != 0, "reverse id origin set");
        CHECK ((r1 & PM_MUX_ID_MASK) != 0, "reverse slot non-zero");
        /* binding a live id then allocating must not hand back the same id */
        pm_relaybind_add (&t2, 0xBEEF, f1);  /* mark f1 in use on b-side */
        /* allocator should skip f1 since it's bound on b-side */
        for (int i = 0; i < 300; i++) {
            unsigned int f = pm_relaybind_alloc (&t2, 0);
            if (f == f1) { CHECK (0, "allocator reused a live b-side id"); break; }
            pm_relaybind_add (&t2, 0x1000u + i, f);
        }
    }

    if (failures) { printf ("RELAYBIND FAIL: %d\n", failures); printf ("RESULT: %d failure(s)\n", failures); return 1; }
    printf ("RELAYBIND OK: binding table add/lookup/del + id allocator\n");
    printf ("RESULT: all passed\n");
    return 0;
}
