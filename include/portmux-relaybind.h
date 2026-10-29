/*
 ============================================================================
 Name        : portmux-relaybind.h
 Description : Reverse-multihop relay binding table. A relay hop owns TWO Noise
               carriers (inbound 'a', outbound 'b') and carries the FULL
               symmetric mux across them: every stream that crosses the hop is
               re-keyed from the a-carrier's id to a freshly-allocated b-carrier
               id (and vice-versa) so the two carriers' id spaces never alias.
               A PmRelayBind records one such a_id<->b_id pairing.

               Each carrier allocates ids from its OWN pool (forward ids with
               the origin bit clear, reverse ids with it set — see
               PM_MUX_ORIGIN in portmux-tunnel.h), so an id is NEVER forwarded
               unchanged: the receiving hop re-allocates and records a binding.
               Collision-freedom therefore holds across an arbitrary chain.

               Pure data structure, no sockets; unit-tested in test_relaybind.c.
 ============================================================================
 */

#ifndef __PORTMUX_RELAYBIND_H__
#define __PORTMUX_RELAYBIND_H__

#include "portmux-tunnel.h"   /* PM_MUX_* id constants */

#ifdef __cplusplus
extern "C" {
#endif

/* Two 255-slot stream spaces per carrier (slots 1..255; 0 reserved), two
   carriers -> at most 2*255 live streams crossing one hop in each direction.
   We size the record pool to cover both carriers' forward+reverse pools. */
#define PM_RELAYBIND_MAX (4 * (PM_MUX_MAX_STREAMS - 1))

/* One a_id<->b_id pairing. in_use==0 marks a free pool slot. */
typedef struct
{
    int          in_use;
    unsigned int a_id;    /* stream id on the inbound (a) carrier  */
    unsigned int b_id;    /* stream id on the outbound (b) carrier */
} PmRelayBind;

/* The binding table + per-carrier id allocators. 'a' is the inbound carrier
   (toward the edge), 'b' is the outbound carrier (toward the terminal). Each
   carrier has independent forward/reverse next-id cursors. */
typedef struct
{
    PmRelayBind binds[PM_RELAYBIND_MAX];
    unsigned int a_next_fwd, a_next_rev;   /* a-carrier id cursors */
    unsigned int b_next_fwd, b_next_rev;   /* b-carrier id cursors */
} PmRelayBindTable;

/* Reset @t to empty. */
void pm_relaybind_init (PmRelayBindTable *t);

/* Record a new a_id<->b_id binding. Returns the stored record, or NULL if the
   pool is full. */
PmRelayBind *pm_relaybind_add (PmRelayBindTable *t,
                               unsigned int a_id, unsigned int b_id);

/* Find a binding by its a-side / b-side id. Returns NULL if none. */
PmRelayBind *pm_relaybind_lookup_a (PmRelayBindTable *t, unsigned int a_id);
PmRelayBind *pm_relaybind_lookup_b (PmRelayBindTable *t, unsigned int b_id);

/* Remove a binding by its a-side / b-side id (no-op if absent). */
void pm_relaybind_del_a (PmRelayBindTable *t, unsigned int a_id);
void pm_relaybind_del_b (PmRelayBindTable *t, unsigned int b_id);

/* Allocate a fresh id in carrier @b_side? b : a, @reverse? reverse-pool :
   forward-pool. The allocator skips 0/0x8000 and any id already recorded on
   that carrier-side of the table, so it never aliases a live stream. Returns a
   valid id, or 0 if the pool is exhausted. */
unsigned int pm_relaybind_alloc (PmRelayBindTable *t, int reverse);
unsigned int pm_relaybind_alloc_side (PmRelayBindTable *t, int b_side, int reverse);

#ifdef __cplusplus
}
#endif

#endif /* __PORTMUX_RELAYBIND_H__ */
