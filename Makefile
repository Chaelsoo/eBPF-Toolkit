OUTPUT  := ebpf-netsec
SRCDIR  := src

# TCP monitor
TCP_BPF_SRC  := $(SRCDIR)/tcp_monitor.bpf.c
TCP_BPF_OBJ  := $(SRCDIR)/tcp_monitor.bpf.o
TCP_BPF_SKEL := $(SRCDIR)/tcp_monitor.skel.h

# TLS interceptor
TLS_BPF_SRC  := $(SRCDIR)/tls_intercept.bpf.c
TLS_BPF_OBJ  := $(SRCDIR)/tls_intercept.bpf.o
TLS_BPF_SKEL := $(SRCDIR)/tls_intercept.skel.h

USER_SRC := $(SRCDIR)/main.c

CLANG   := clang
CC      := gcc
BPFTOOL := bpftool

ARCH := x86

BPF_CFLAGS := \
	-g -O2 -target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-I$(SRCDIR) \
	-Wall \
	-Wno-unused-variable

USER_CFLAGS  := -O2 -I$(SRCDIR) -Wall
USER_LDFLAGS := -lbpf -lelf -lz

.PHONY: all clean

all: $(OUTPUT)

# ── BPF objects ──────────────────────────────────────────────────────────────

$(TCP_BPF_OBJ): $(TCP_BPF_SRC) $(SRCDIR)/vmlinux.h $(SRCDIR)/tcp_monitor.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(TLS_BPF_OBJ): $(TLS_BPF_SRC) $(SRCDIR)/vmlinux.h $(SRCDIR)/tls_intercept.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# ── Skeleton headers ─────────────────────────────────────────────────────────

$(TCP_BPF_SKEL): $(TCP_BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(TLS_BPF_SKEL): $(TLS_BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# ── Userspace binary ─────────────────────────────────────────────────────────

$(OUTPUT): $(TCP_BPF_SKEL) $(TLS_BPF_SKEL) $(USER_SRC) \
           $(SRCDIR)/tcp_monitor.h $(SRCDIR)/tls_intercept.h
	$(CC) $(USER_CFLAGS) $(USER_SRC) -o $@ $(USER_LDFLAGS)

# ── Cleanup ──────────────────────────────────────────────────────────────────

clean:
	rm -f $(TCP_BPF_OBJ) $(TCP_BPF_SKEL) \
	      $(TLS_BPF_OBJ) $(TLS_BPF_SKEL) \
	      $(OUTPUT)
