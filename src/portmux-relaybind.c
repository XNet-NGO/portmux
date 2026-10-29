/*
 ============================================================================
 Name        : portmux-relaybind.c
 Description : Reverse-multihop relay binding table (see portmux-relaybind.h).
 ============================================================================
 */

#include <string.h>

#include "portmux-relaybind.h"

void
pm_relaybind_init (PmRelayBindTable *t)
{
    memset (t, 0, sizeof *t);
    t->a_next_fwd = t->a_next_rev = 1;
    t->b_next_fwd = t->b_next_rev = 1;
}

PmRelayBind *
pm_relaybind_add (PmRelayBindTable *t, unsigned int a_id, unsigned int b_id)
{
    for (int i = 0; i < PM_RELAYBIND_MAX; i++) {
        if (!t->binds[i].in_use) {
            t->binds[i].in_use = 1;
            t->binds[i].a_id = a_id;
            t->binds[i].b_id = b_id;
            return &t->binds[i];
        }
    }
    return NULL;   /* pool full */
}

PmRelayBind *
pm_relaybind_lookup_a (PmRelayBindTable *t, unsigned int a_id)
{
    for (int i = 0; i < PM_RELAYBIND_MAX; i++)
        if (t->binds[i].in_use && t->binds[i].a_id == a_id)
            return &t->binds[i];
    return NULL;
}

PmRelayBind *
pm_relaybind_lookup_b (PmRelayBindTable *t, unsigned int b_id)
{
    for (int i = 0; i < PM_RELAYBIND_MAX; i++)
        if (t->binds[i].in_use && t->binds[i].b_id == b_id)
            return &t->binds[i];
    return NULL;
}

void
pm_relaybind_del_a (PmRelayBindTable *t, unsigned int a_id)
{
    PmRelayBind *b = pm_relaybind_lookup_a (t, a_id);
    if (b) b->in_use = 0;
}

void
pm_relaybind_del_b (PmRelayBindTable *t, unsigned int b_id)
{
    PmRelayBind *b = pm_relaybind_lookup_b (t, b_id);
    if (b) b->in_use = 0;
}

/* Is @id already recorded on the given carrier side of the table? */
static int
side_id_live (PmRelayBindTable *t, int b_side, unsigned int id)
{
    for (int i = 0; i < PM_RELAYBIND_MAX; i++) {
        if (!t->binds[i].in_use) continue;
        unsigned int v = b_side ? t->binds[i].b_id : t->binds[i].a_id;
        if (v == id) return 1;
    }
    return 0;
}

unsigned int
pm_relaybind_alloc_side (PmRelayBindTable *t, int b_side, int reverse)
{
    unsigned int *cursor = b_side
        ? (reverse ? &t->b_next_rev : &t->b_next_fwd)
        : (reverse ? &t->a_next_rev : &t->a_next_fwd);
    unsigned int origin = reverse ? PM_MUX_ORIGIN : 0u;

    for (unsigned int k = 0; k < PM_MUX_MAX_STREAMS; k++) {
        unsigned int slot = (*cursor + k) % PM_MUX_MAX_STREAMS;
        if (slot == 0) continue;                 /* 0 / 0x8000 reserved */
        unsigned int id = origin | slot;
        if (side_id_live (t, b_side, id)) continue;
        *cursor = (slot + 1) % PM_MUX_MAX_STREAMS;
        return id;
    }
    return 0;                                     /* pool exhausted */
}

unsigned int
pm_relaybind_alloc (PmRelayBindTable *t, int reverse)
{
    /* default: allocate on the OUTBOUND (b) carrier — the common case where an
       a-side stream crosses the hop and needs a fresh b-side id. */
    return pm_relaybind_alloc_side (t, 1 /*b_side*/, reverse);
}
