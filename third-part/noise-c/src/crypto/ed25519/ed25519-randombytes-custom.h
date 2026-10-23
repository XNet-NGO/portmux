/* ed25519 signing is NOT used by the NoisePSK_NN handshake. ed25519.c is
   compiled only for curved25519_scalarmult_basepoint. Its randombytes is
   provided by the protocol layer (src/protocol/rand_os.c, /dev/urandom), so
   here we only forward-declare it — avoiding both the OpenSSL include and a
   duplicate definition. */
#include <stddef.h>
void ed25519_randombytes_unsafe (void *p, size_t len);
