# Vendored noise-c (minimal, reference backend)

This is a **pruned, self-contained subset** of [noise-c](https://github.com/rweather/noise-c)
(the Noise Protocol Framework C reference implementation, MIT — see `COPYING`),
vendored for portmux's encrypted rendezvous tunnel (`portmux-tunnel.h`).

## What it provides

Exactly enough to run the handshake:

```
NoisePSK_NN_25519_AESGCM_BLAKE2s      (preferred; ARMv8 HW-AES)
NoisePSK_NN_25519_ChaChaPoly_BLAKE2s  (fallback; no AES hardware)
```

`NoisePSK_NN` is this library's spelling of the **NNpsk0** construction:
ephemeral-ephemeral X25519 (forward secrecy) authenticated by a 32-byte
pre-shared key. No certificates, no PKI — "IP + key".

## Why it's self-contained

- **Reference backend only** (`src/backend/ref`) — no system libsodium, no
  OpenSSL. The crypto primitives (ChaCha20, Poly1305, AES/rijndael, BLAKE2s/b,
  SHA-256/512, GHASH, Curve25519-donna) are all vendored under `src/crypto`.
- Compiles by listing the sources directly (see `noise-c.mk`); the upstream
  autotools build is **not** used, so it drops straight into portmux's `make`
  and the Android NDK CMake the same way hev-task does.

## What was pruned (not needed for NN_25519)

- `src/backend/sodium`, `src/backend/openssl` — alternate backends.
- `src/crypto/curve448`, `src/crypto/goldilocks`, `src/crypto/newhope` — DH
  methods NN_25519 never uses.
- ed25519 `fuzz/` and `test.c`.
- The ref backend's `dh-curve448.c`, `dh-newhope.c`, `sign-ed25519.c`.

`src/noise-unused-backends.c` provides NULL-returning stubs for
`noise_curve448_new` / `noise_newhope_new` / `noise_ed25519_new`, which
`dhstate.c`/`signstate.c` reference unconditionally. `src/crypto/ed25519/ed25519.c`
is kept **only** because it provides `curved25519_scalarmult_basepoint` used by
the Curve25519 DH; its signing is never invoked. ed25519 randombytes resolves to
the protocol layer's OS RNG (`src/protocol/rand_os.c`, `/dev/urandom`); the
config (`gen/noise/defines/config.h`) sets `ED25519_REFHASH` and
`ED25519_CUSTOMRANDOM` with a forward-decl-only custom header so no OpenSSL is
pulled and there is no duplicate definition.

## Upstream

Pinned from https://github.com/rweather/noise-c (HEAD at vendor time). To
refresh, re-copy `include/`, `src/protocol`, `src/backend/ref`, and the listed
`src/crypto` subdirs, then re-apply the prune list above.
