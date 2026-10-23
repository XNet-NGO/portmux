/* portmux-vendored minimal config for noise-c reference backend.
   NoisePSK_NN over Curve25519 + ChaChaPoly/AESGCM + BLAKE2s. No system
   libsodium/openssl. ed25519 uses the reference SHA-512 hash; its randombytes
   is the protocol OS RNG (rand_os.c). ed25519 signing is unused (stubbed);
   ed25519.c is compiled only for the Curve25519 scalarmult basepoint. */
#define ED25519_REFHASH 1
#define ED25519_CUSTOMRANDOM 1
