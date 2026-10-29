# Makefile for portmux — userspace TCP/UDP port forwarder (lwIP-free)

CROSS_PREFIX :=
CC      = $(CROSS_PREFIX)gcc
AR      = $(CROSS_PREFIX)ar

SRCDIR   = src
INCDIR   = include
BUILDDIR = build
BINDIR   = bin
TPDIR    = third-part
HTS      = $(TPDIR)/hev-task-system

# Vendored noise-c (NoisePSK_NN tunnel crypto). Defines NOISE_DIR/NOISE_INC/
# NOISE_DEFS/NOISE_SRCS.
include $(TPDIR)/noise-c/noise-c.mk

# Version string for the CLI (--version). Derived from the git tag; override
# with `make PORTMUX_VERSION=vX.Y.Z` for out-of-tree/source-tarball builds.
PORTMUX_VERSION ?= $(shell git -C $(CURDIR) describe --tags --always --dirty 2>/dev/null || echo v0.7.0)

# Internal flags are kept separate from the user-facing CFLAGS so that a
# command-line `make CFLAGS=...` augments rather than clobbers our includes.
# Pass extra flags via CFLAGS or EXTRA_CFLAGS (e.g. CFLAGS=-fPIC).
PM_CFLAGS = -O3 -pipe -Wall -Wextra -std=gnu11 \
            -I$(INCDIR) -I$(SRCDIR) -I$(HTS)/include \
            -DPORTMUX_VERSION='"$(PORTMUX_VERSION)"' \
            $(CFLAGS) $(EXTRA_CFLAGS)
LDFLAGS += -L$(HTS)/bin -lhev-task-system -lpthread

LIB_SRCS = $(SRCDIR)/portmux.c \
           $(SRCDIR)/portmux-egress.c \
           $(SRCDIR)/portmux-socks.c \
           $(SRCDIR)/portmux-tunnel.c \
           $(SRCDIR)/portmux-relaybind.c \
           $(SRCDIR)/portmux-addr.c
LIB_OBJS = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(LIB_SRCS))

# noise-c objects (compiled with the noise include/defines, warnings relaxed
# since it is vendored third-party code).
NOISE_OBJS = $(patsubst $(NOISE_DIR)/%.c,$(BUILDDIR)/noise/%.o,$(NOISE_SRCS))

CLI_SRC  = $(SRCDIR)/main.c
CLI_OBJ  = $(BUILDDIR)/main.o

STATIC   = $(BINDIR)/libportmux.a
CLI      = $(BINDIR)/portmux

HTS_LIB  = $(HTS)/bin/libhev-task-system.a

.PHONY: all clean hts test

all: $(CLI) $(STATIC)

$(HTS_LIB):
	@echo "BUILD hev-task-system"
	$(MAKE) -C $(HTS) static

hts: $(HTS_LIB)

$(BUILDDIR)/%.o: $(SRCDIR)/%.c | $(BUILDDIR)
	@echo "CC    $<"
	$(CC) $(PM_CFLAGS) $(NOISE_INC) $(NOISE_DEFS) -c $< -o $@

# Vendored noise-c: relax warnings (third-party), keep our includes/defines.
$(BUILDDIR)/noise/%.o: $(NOISE_DIR)/%.c
	@mkdir -p $(dir $@)
	@echo "CC    $< (noise)"
	$(CC) -O2 -std=gnu11 -w $(CFLAGS) $(EXTRA_CFLAGS) $(NOISE_INC) $(NOISE_DEFS) -c $< -o $@

$(STATIC): $(LIB_OBJS) $(NOISE_OBJS)
	@mkdir -p $(BINDIR)
	@echo "AR    $@"
	$(AR) rcs $@ $(LIB_OBJS) $(NOISE_OBJS)

$(CLI): $(HTS_LIB) $(LIB_OBJS) $(NOISE_OBJS) $(CLI_OBJ) | $(BINDIR)
	@echo "LINK  $@"
	$(CC) $(PM_CFLAGS) $(LIB_OBJS) $(NOISE_OBJS) $(CLI_OBJ) -o $@ $(LDFLAGS)

$(BUILDDIR):
	@mkdir -p $(BUILDDIR)

$(BINDIR):
	@mkdir -p $(BINDIR)

test: $(STATIC) $(HTS_LIB) $(CLI)
	@echo "CC    tests/test_relay"
	$(CC) $(PM_CFLAGS) tests/test_relay.c $(STATIC) -o $(BUILDDIR)/test_relay $(LDFLAGS)
	@echo "RUN   test_relay"
	@$(BUILDDIR)/test_relay
	@echo "CC    tests/test_udp_evict (short timeouts)"
	$(CC) $(PM_CFLAGS) $(NOISE_INC) $(NOISE_DEFS) -DPM_UDP_IDLE_MS=800 -DPM_UDP_SWEEP_MS=200 \
		$(LIB_SRCS) $(NOISE_SRCS) tests/test_udp_evict.c -o $(BUILDDIR)/test_udp_evict $(LDFLAGS)
	@echo "RUN   test_udp_evict"
	@$(BUILDDIR)/test_udp_evict
	@echo "CC    tests/test_socks"
	$(CC) $(PM_CFLAGS) tests/test_socks.c $(STATIC) -o $(BUILDDIR)/test_socks $(LDFLAGS)
	@echo "RUN   test_socks"
	@$(BUILDDIR)/test_socks
	@echo "CC    tests/test_tunnel"
	$(CC) $(PM_CFLAGS) $(NOISE_INC) $(NOISE_DEFS) tests/test_tunnel.c $(STATIC) -o $(BUILDDIR)/test_tunnel $(LDFLAGS)
	@echo "RUN   test_tunnel"
	@$(BUILDDIR)/test_tunnel
	@echo "CC    tests/test_jumplist"
	$(CC) $(PM_CFLAGS) $(NOISE_INC) $(NOISE_DEFS) tests/test_jumplist.c $(STATIC) -o $(BUILDDIR)/test_jumplist $(LDFLAGS)
	@echo "RUN   test_jumplist"
	@$(BUILDDIR)/test_jumplist
	@echo "CC    tests/test_relaybind"
	$(CC) $(PM_CFLAGS) $(NOISE_INC) $(NOISE_DEFS) tests/test_relaybind.c $(STATIC) -o $(BUILDDIR)/test_relaybind $(LDFLAGS)
	@echo "RUN   test_relaybind"
	@$(BUILDDIR)/test_relaybind
	@echo "CC    tests/test_jump"
	$(CC) $(PM_CFLAGS) $(NOISE_INC) $(NOISE_DEFS) tests/test_jump.c $(STATIC) -o $(BUILDDIR)/test_jump $(LDFLAGS)
	@echo "RUN   test_jump"
	@$(BUILDDIR)/test_jump
	@echo "CC    tests/test_rjump"
	$(CC) $(PM_CFLAGS) $(NOISE_INC) $(NOISE_DEFS) tests/test_rjump.c $(STATIC) -o $(BUILDDIR)/test_rjump $(LDFLAGS)
	@echo "RUN   test_rjump"
	@$(BUILDDIR)/test_rjump
	@echo "CC    tests/test_cli"
	$(CC) $(PM_CFLAGS) tests/test_cli.c -o $(BUILDDIR)/test_cli
	@echo "RUN   test_cli (execs bin/portmux)"
	@$(BUILDDIR)/test_cli

clean:
	rm -rf $(BUILDDIR) $(BINDIR)
	$(MAKE) -C $(HTS) clean || true
