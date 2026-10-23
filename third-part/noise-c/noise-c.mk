# Auto-generated list of vendored noise-c sources for the NoisePSK_NN
# tunnel. Reference backend only; no libsodium/openssl. See README.
NOISE_DIR = third-part/noise-c
NOISE_INC = -I$(NOISE_DIR)/include -I$(NOISE_DIR)/src -I$(NOISE_DIR)/src/protocol -I$(NOISE_DIR)/gen
NOISE_DEFS = -DED25519_REFHASH -DED25519_CUSTOMRANDOM
NOISE_SRCS = \
  $(NOISE_DIR)/src/protocol/cipherstate.c \
  $(NOISE_DIR)/src/protocol/dhstate.c \
  $(NOISE_DIR)/src/protocol/errors.c \
  $(NOISE_DIR)/src/protocol/handshakestate.c \
  $(NOISE_DIR)/src/protocol/hashstate.c \
  $(NOISE_DIR)/src/protocol/internal.c \
  $(NOISE_DIR)/src/protocol/names.c \
  $(NOISE_DIR)/src/protocol/patterns.c \
  $(NOISE_DIR)/src/protocol/rand_os.c \
  $(NOISE_DIR)/src/protocol/randstate.c \
  $(NOISE_DIR)/src/protocol/signstate.c \
  $(NOISE_DIR)/src/protocol/symmetricstate.c \
  $(NOISE_DIR)/src/protocol/util.c \
  $(NOISE_DIR)/src/backend/ref/cipher-aesgcm.c \
  $(NOISE_DIR)/src/backend/ref/cipher-chachapoly.c \
  $(NOISE_DIR)/src/backend/ref/dh-curve25519.c \
  $(NOISE_DIR)/src/backend/ref/hash-blake2b.c \
  $(NOISE_DIR)/src/backend/ref/hash-blake2s.c \
  $(NOISE_DIR)/src/backend/ref/hash-sha256.c \
  $(NOISE_DIR)/src/backend/ref/hash-sha512.c \
  $(NOISE_DIR)/src/crypto/chacha/chacha.c \
  $(NOISE_DIR)/src/crypto/aes/rijndael-alg-fst.c \
  $(NOISE_DIR)/src/crypto/blake2/blake2s.c \
  $(NOISE_DIR)/src/crypto/blake2/blake2b.c \
  $(NOISE_DIR)/src/crypto/sha2/sha256.c \
  $(NOISE_DIR)/src/crypto/sha2/sha512.c \
  $(NOISE_DIR)/src/crypto/ghash/ghash.c \
  $(NOISE_DIR)/src/crypto/donna/poly1305-donna.c \
  $(NOISE_DIR)/src/crypto/ed25519/ed25519.c \
  $(NOISE_DIR)/src/noise-unused-backends.c \

