/* NoisePSK_NN_25519 uses only Curve25519 DH and no signatures. noise-c's
   dhstate.c/signstate.c reference these constructors unconditionally, so we
   provide NULL-returning stubs ("algorithm unsupported") to avoid compiling
   the Curve448/NewHope/Ed25519 backends and their large dependency trees. */
#include <noise/protocol.h>
NoiseDHState   *noise_curve448_new (void) { return 0; }
NoiseDHState   *noise_newhope_new  (void) { return 0; }
NoiseSignState *noise_ed25519_new  (void) { return 0; }
