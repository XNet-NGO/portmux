#!/usr/bin/env bash
# Cross-build the portmux CLI for all feasible Linux targets and package per-
# target tarballs + a SHA256SUMS file for a release. No Android NDK needed
# (that is scripts/build-release.sh). portmux is Linux-only.
#
# Toolchains (install what you have; missing ones are SKIPped):
#   linux-x86_64        native gcc
#   linux-x86_64-musl   musl-gcc           (apt: musl-tools)          [static]
#   linux-aarch64       aarch64-linux-gnu-gcc   (gcc-aarch64-linux-gnu)
#   linux-armv7         arm-linux-gnueabihf-gcc (gcc-arm-linux-gnueabihf)
#   linux-riscv64       riscv64-linux-gnu-gcc   (gcc-riscv64-linux-gnu)
#
# Output: dist-cli/portmux-<version>-<target>.tar.gz + -cli-SHA256SUMS.txt
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
VERSION="$(git -C "$ROOT" describe --tags --always 2>/dev/null || echo dev)"
OUT="$ROOT/dist-cli"
HTS="third-part/hev-task-system"
rm -rf "$OUT"; mkdir -p "$OUT"

build() { # build NAME CROSS_PREFIX [CC] [STATIC]
  local name="$1" cross="${2:-}" cc="${3:-}" static="${4:-}"
  local probe="${cc:-${cross}gcc}"
  if ! command -v "$probe" >/dev/null 2>&1; then
    echo "SKIP $name ($probe not found)"; return 0
  fi
  echo "=== $name ==="
  make -C "$HTS" clean >/dev/null 2>&1 || true
  local mkargs=()
  [ -n "$cross" ] && mkargs+=("CROSS_PREFIX=$cross")
  [ -n "$cc" ]    && mkargs+=("CC=$cc")
  make "${mkargs[@]}" -C "$HTS" static >/dev/null
  local extra="" ldextra=""
  if [ -n "$static" ]; then extra="-static"; ldextra="-static"; fi
  make "${mkargs[@]}" BUILDDIR="build-$name" BINDIR="bin-$name" \
       EXTRA_CFLAGS="$extra" \
       ${ldextra:+LDFLAGS="$ldextra -L$HTS/bin -lhev-task-system -lpthread"} \
       "bin-$name/portmux" >/dev/null
  mkdir -p "$OUT/stage-$name"
  cp "bin-$name/portmux" "$OUT/stage-$name/"
  cp README.md "$OUT/stage-$name/" 2>/dev/null || true
  tar -C "$OUT/stage-$name" -czf "$OUT/portmux-$VERSION-$name.tar.gz" portmux README.md
  rm -rf "$OUT/stage-$name"
  file "bin-$name/portmux" | sed 's/.*: //' | cut -d, -f1-2 | sed 's/^/    /'
}

build linux-x86_64        ""
build linux-x86_64-musl   ""                      musl-gcc  static
build linux-aarch64       "aarch64-linux-gnu-"
build linux-armv7         "arm-linux-gnueabihf-"
build linux-riscv64       "riscv64-linux-gnu-"

# restore the native host build (cross builds clobbered $HTS)
make -C "$HTS" clean >/dev/null 2>&1 || true
make -C "$HTS" static >/dev/null 2>&1 || true
make >/dev/null 2>&1 || true

( cd "$OUT" && sha256sum portmux-"$VERSION"-*.tar.gz > "portmux-$VERSION-cli-SHA256SUMS.txt" )
echo "=== CLI artifacts ($VERSION) ==="
ls -lh "$OUT"/*.tar.gz "$OUT"/*SHA256SUMS* 2>/dev/null | sed 's/^/  /'
echo "=== SHA256SUMS ==="
cat "$OUT/portmux-$VERSION-cli-SHA256SUMS.txt"
