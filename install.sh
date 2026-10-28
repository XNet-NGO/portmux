#!/bin/sh
# portmux installer — detects your platform, downloads the matching prebuilt CLI
# from the GitHub release, verifies its SHA-256, and installs it.
#
#   curl -fsSL https://raw.githubusercontent.com/XNet-NGO/portmux/master/install.sh | sh
#
# Environment overrides:
#   PORTMUX_VERSION   release tag to install           (default: latest)
#   PORTMUX_PREFIX    install dir                       (default: /usr/local/bin,
#                                                        else ~/.local/bin)
#   PORTMUX_TARGET    force a target (e.g. linux-x86_64-musl) instead of detecting
#
# portmux is Linux-only (epoll + an ELF coroutine context switch). The musl
# build is fully static and runs on any Linux regardless of libc; the glibc
# builds need a glibc at least as new as the build host's.
set -eu

REPO="XNet-NGO/portmux"
VERSION="${PORTMUX_VERSION:-latest}"

say()  { printf '%s\n' "$*" >&2; }
die()  { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---- detect target ---------------------------------------------------------
detect_target() {
    [ -n "${PORTMUX_TARGET:-}" ] && { printf '%s' "$PORTMUX_TARGET"; return; }

    os="$(uname -s)"
    [ "$os" = "Linux" ] || die "portmux supports Linux only (got '$os'). Build from source for other systems."

    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)
            # Prefer the fully-static musl build: no glibc version coupling.
            printf '%s' "linux-x86_64-musl" ;;
        aarch64|arm64)   printf '%s' "linux-aarch64" ;;
        armv7l|armv7|armhf|arm) printf '%s' "linux-armv7" ;;
        riscv64)         printf '%s' "linux-riscv64" ;;
        *) die "unsupported architecture '$arch'. Supported: x86_64, aarch64, armv7l, riscv64. Build from source or set PORTMUX_TARGET." ;;
    esac
}

# ---- resolve version -------------------------------------------------------
resolve_version() {
    [ "$VERSION" != "latest" ] && { printf '%s' "$VERSION"; return; }
    # Resolve 'latest' via the redirect of the releases/latest URL (no API token).
    url="https://github.com/$REPO/releases/latest"
    if have curl; then
        loc="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$url" 2>/dev/null || true)"
    elif have wget; then
        loc="$(wget -q -S -O /dev/null "$url" 2>&1 | awk '/Location:/{print $2}' | tail -1)"
    fi
    tag="${loc##*/tag/}"
    [ -n "$tag" ] && [ "$tag" != "$loc" ] && printf '%s' "$tag" || die "could not resolve latest version; set PORTMUX_VERSION."
}

# ---- download helper -------------------------------------------------------
dl() { # dl URL OUTFILE
    if have curl; then curl -fsSL "$1" -o "$2"
    elif have wget; then wget -qO "$2" "$1"
    else die "need curl or wget"; fi
}

main() {
    target="$(detect_target)"
    ver="$(resolve_version)"
    say "portmux: installing $ver for $target"

    base="https://github.com/$REPO/releases/download/$ver"
    tarball="portmux-$ver-$target.tar.gz"
    sums="portmux-$ver-cli-SHA256SUMS.txt"

    tmp="$(mktemp -d "${TMPDIR:-/tmp}/portmux.XXXXXX")"
    trap 'rm -rf "$tmp"' EXIT INT TERM

    say "  downloading $tarball"
    dl "$base/$tarball" "$tmp/$tarball" || die "download failed: $base/$tarball"

    # verify SHA-256 against the published SHA256SUMS (best-effort if present)
    if dl "$base/$sums" "$tmp/$sums" 2>/dev/null; then
        want="$(awk -v f="$tarball" '$2==f{print $1}' "$tmp/$sums")"
        if [ -n "$want" ]; then
            if have sha256sum; then got="$(sha256sum "$tmp/$tarball" | awk '{print $1}')"
            elif have shasum; then got="$(shasum -a 256 "$tmp/$tarball" | awk '{print $1}')"
            else got=""; say "  (no sha256 tool; skipping checksum)"; fi
            if [ -n "$got" ]; then
                [ "$got" = "$want" ] || die "checksum mismatch for $tarball (got $got, want $want)"
                say "  sha256 OK"
            fi
        fi
    else
        say "  (no SHA256SUMS published for $ver; skipping checksum)"
    fi

    tar -xzf "$tmp/$tarball" -C "$tmp" portmux || die "extract failed"
    chmod +x "$tmp/portmux"

    # choose an install dir we can write to
    if [ -n "${PORTMUX_PREFIX:-}" ]; then dest="$PORTMUX_PREFIX"
    elif [ -w /usr/local/bin ] 2>/dev/null; then dest="/usr/local/bin"
    elif [ "$(id -u)" = "0" ]; then dest="/usr/local/bin"
    else dest="$HOME/.local/bin"; fi
    mkdir -p "$dest" 2>/dev/null || true

    if [ -w "$dest" ] 2>/dev/null || [ "$(id -u)" = "0" ]; then
        install -m 0755 "$tmp/portmux" "$dest/portmux"
    elif have sudo; then
        say "  installing to $dest (needs sudo)"
        sudo install -m 0755 "$tmp/portmux" "$dest/portmux"
    else
        die "cannot write to $dest and sudo not available; set PORTMUX_PREFIX to a writable dir."
    fi

    say "portmux installed: $dest/portmux"
    "$dest/portmux" 2>&1 | head -1 >&2 || true
    case ":$PATH:" in
        *":$dest:"*) : ;;
        *) say "note: $dest is not on your PATH — add it, e.g.  export PATH=\"$dest:\$PATH\"" ;;
    esac
}

main "$@"
