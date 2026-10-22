#!/usr/bin/env bash
# Build portmux release artifacts:
#   - host Linux x86_64: static lib + CLI (and run tests)
#   - Android ABIs (arm64-v8a, armeabi-v7a, x86_64, x86): static lib + header
#
# Output layout under dist/:
#   dist/android/<abi>/libportmux.a
#   dist/android/<abi>/libhev-task-system.a
#   dist/include/portmux.h
#   dist/linux-x86_64/{libportmux.a,portmux}
#
# Requires: ANDROID_NDK_HOME pointing at an NDK (r23+). API level via API=.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

API="${API:-21}"
NDK="${ANDROID_NDK_HOME:-}"
DIST="$ROOT/dist"
VERSION="$(git -C "$ROOT" describe --tags --always 2>/dev/null || echo dev)"

# Keep gcc/clang temp files off a possibly-full /tmp. Must live outside build/
# since the build loop runs `make clean` (which wipes build/).
export TMPDIR="${TMPDIR:-$ROOT/.buildtmp}"
mkdir -p "$TMPDIR"

if [ -z "$NDK" ] || [ ! -d "$NDK" ]; then
  echo "ERROR: ANDROID_NDK_HOME is not set or not a directory" >&2
  exit 1
fi

HOST_TAG="linux-x86_64"
TC="$NDK/toolchains/llvm/prebuilt/$HOST_TAG"
if [ ! -d "$TC" ]; then
  echo "ERROR: NDK toolchain not found at $TC" >&2
  exit 1
fi

LLVM_AR="$TC/bin/llvm-ar"
if [ ! -x "$LLVM_AR" ]; then LLVM_AR="$TC/bin/llvm-ar"; fi

rm -rf "$DIST"
mkdir -p "$DIST/include" "$DIST/$HOST_TAG"

# ---- Android ABI -> clang triple map ----
# abi:triple
ABIS=(
  "arm64-v8a:aarch64-linux-android"
  "armeabi-v7a:armv7a-linux-androideabi"
  "x86_64:x86_64-linux-android"
  "x86:i686-linux-android"
)

build_android () {
  local abi="$1" triple="$2"
  local cc="$TC/bin/${triple}${API}-clang"
  if [ ! -x "$cc" ]; then
    echo "SKIP $abi: $cc not found" >&2
    return 0
  fi
  echo "=== Android $abi ($triple, API $API) ==="
  make clean >/dev/null 2>&1 || true
  # Build hev-task-system static for this ABI
  make -C third-part/hev-task-system clean >/dev/null 2>&1 || true
  make -C third-part/hev-task-system static \
      CC="$cc" AR="$LLVM_AR" CROSS_PREFIX= >/dev/null
  # Build portmux static lib for this ABI (library only, not CLI)
  make bin/libportmux.a CC="$cc" AR="$LLVM_AR" CROSS_PREFIX= >/dev/null
  mkdir -p "$DIST/android/$abi"
  cp bin/libportmux.a "$DIST/android/$abi/"
  cp third-part/hev-task-system/bin/libhev-task-system.a "$DIST/android/$abi/"
  echo "    -> dist/android/$abi/{libportmux.a,libhev-task-system.a}"
}

for pair in "${ABIS[@]}"; do
  build_android "${pair%%:*}" "${pair##*:}"
done

# ---- Host Linux build + tests ----
echo "=== Host $HOST_TAG (with tests) ==="
make clean >/dev/null 2>&1 || true
make all >/dev/null
make test
cp bin/libportmux.a bin/portmux "$DIST/$HOST_TAG/"
cp third-part/hev-task-system/bin/libhev-task-system.a "$DIST/$HOST_TAG/"

# ---- Public header ----
cp include/portmux.h "$DIST/include/"

# ---- Manifest ----
cat > "$DIST/MANIFEST.txt" <<EOF
portmux prebuilt artifacts
version:   $VERSION
ndk:       $(basename "$NDK")
api level: $API
built:     $(date -u +%Y-%m-%dT%H:%M:%SZ)

Android static libraries (link both .a into your NDK target):
$(cd "$DIST" && find android -type f | sort | sed 's/^/  /')

Host:
$(cd "$DIST" && find "$HOST_TAG" -type f | sort | sed 's/^/  /')

Header:
  include/portmux.h
EOF
echo "=== MANIFEST ==="
cat "$DIST/MANIFEST.txt"

# ---- Package tarball ----
TARBALL="$ROOT/portmux-${VERSION}-artifacts.tar.gz"
tar -C "$DIST" -czf "$TARBALL" .
echo "=== Packaged: $TARBALL ==="
ls -lh "$TARBALL"
