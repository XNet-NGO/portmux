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

# Internal flags are kept separate from the user-facing CFLAGS so that a
# command-line `make CFLAGS=...` augments rather than clobbers our includes.
# Pass extra flags via CFLAGS or EXTRA_CFLAGS (e.g. CFLAGS=-fPIC).
PM_CFLAGS = -O3 -pipe -Wall -Wextra -std=gnu11 \
            -I$(INCDIR) -I$(SRCDIR) -I$(HTS)/include \
            $(CFLAGS) $(EXTRA_CFLAGS)
LDFLAGS += -L$(HTS)/bin -lhev-task-system -lpthread

LIB_SRCS = $(SRCDIR)/portmux.c \
           $(SRCDIR)/portmux-egress.c \
           $(SRCDIR)/portmux-addr.c
LIB_OBJS = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(LIB_SRCS))

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
	$(CC) $(PM_CFLAGS) -c $< -o $@

$(STATIC): $(LIB_OBJS)
	@mkdir -p $(BINDIR)
	@echo "AR    $@"
	$(AR) rcs $@ $(LIB_OBJS)

$(CLI): $(HTS_LIB) $(LIB_OBJS) $(CLI_OBJ) | $(BINDIR)
	@echo "LINK  $@"
	$(CC) $(PM_CFLAGS) $(LIB_OBJS) $(CLI_OBJ) -o $@ $(LDFLAGS)

$(BUILDDIR):
	@mkdir -p $(BUILDDIR)

$(BINDIR):
	@mkdir -p $(BINDIR)

test: $(STATIC) $(HTS_LIB)
	@echo "CC    tests/test_relay"
	$(CC) $(PM_CFLAGS) tests/test_relay.c $(STATIC) -o $(BUILDDIR)/test_relay $(LDFLAGS)
	@echo "RUN   test_relay"
	@$(BUILDDIR)/test_relay
	@echo "CC    tests/test_udp_evict (short timeouts)"
	$(CC) $(PM_CFLAGS) -DPM_UDP_IDLE_MS=800 -DPM_UDP_SWEEP_MS=200 \
		$(LIB_SRCS) tests/test_udp_evict.c -o $(BUILDDIR)/test_udp_evict $(LDFLAGS)
	@echo "RUN   test_udp_evict"
	@$(BUILDDIR)/test_udp_evict

clean:
	rm -rf $(BUILDDIR) $(BINDIR)
	$(MAKE) -C $(HTS) clean || true
