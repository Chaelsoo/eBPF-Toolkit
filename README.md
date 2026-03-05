# ebpf-netsec

A Linux network security visibility tool built with eBPF. It hooks into kernel TCP functions and OpenSSL library calls to monitor connections and intercept TLS plaintext in real time, with minimal overhead.

## What it does

**TCP monitoring** -- kprobes on `tcp_connect`, `tcp_sendmsg`, `tcp_recvmsg`, and `tcp_close` capture every TCP connection lifecycle event per process, including source/destination IPs, ports, byte counts, and process info.

**TLS interception** -- uprobes on `SSL_write` and `SSL_read` (OpenSSL) capture plaintext data before encryption and after decryption. This lets you see what applications are actually sending and receiving over HTTPS without breaking the TLS session.

```
TIME      COMM              PID     SRC                    DST                    BYTES       TYPE
--------  ----------------  ------  ---------------------  ---------------------  ----------  -------
14:57:52  curl              2922242  192.168.1.10:49416     104.18.26.120:443      0           CONNECT
14:57:52  curl              2922242  192.168.1.10:49416     104.18.26.120:443      630         OUTBOUND
TLS  curl              2922242  OUTBOUND    24 bytes  PRI * HTTP/2.0....SM....
TLS  curl              2922242  INBOUND    537 bytes  ...<!doctype html><html lang="en"><head><title>Example Domain</title>...
14:57:53  curl              2922242  192.168.1.10:49416     104.18.26.120:443      0           CLOSE
```

## Architecture

```
 KERNEL SPACE (eBPF)                        USERSPACE (C + libbpf)
+-----------------------------------+      +---------------------------+
| tcp_monitor.bpf.c                 |      | main.c                    |
|   kprobe/tcp_connect              |      |   Load BPF skeletons      |
|   kprobe/tcp_sendmsg              | ---> |   Attach kprobes/uprobes  |
|   kprobe/tcp_recvmsg              | perf |   Poll perf buffers       |
|   kprobe/tcp_close                | buf  |   Format & print events   |
+-----------------------------------+      +---------------------------+
| tls_intercept.bpf.c              |      |                           |
|   uprobe/SSL_write   (entry)     | ---> |   Parse TLS plaintext     |
|   uprobe/SSL_read    (entry)     | perf |   Show first 120 bytes    |
|   uretprobe/SSL_read (return)    | buf  |                           |
+-----------------------------------+      +---------------------------+
```

## Requirements

- Linux kernel 5.15+ with BPF, kprobe, and uprobe support
- x86-64 architecture
- Root privileges (or `CAP_SYS_ADMIN` + `CAP_PERFMON`)
- OpenSSL `libssl.so` installed (for TLS interception)

Tested on Ubuntu Server 22.04 LTS (kernel 5.15). Ubuntu Server is a good fit for this tool since most server-side services (Apache, nginx, curl, Python) dynamically link against the system `libssl.so`, making their TLS traffic visible to the uprobes out of the box.

### Build dependencies (Ubuntu/Debian)

```bash
sudo apt install -y clang llvm libelf-dev libbpf-dev \
    linux-tools-$(uname -r) linux-tools-common gcc-multilib make pkg-config
```

## Building

Generate the kernel type header (one-time, or after kernel updates):

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/vmlinux.h
```

Build:

```bash
make
```

This compiles the BPF programs with `clang`, generates skeleton headers with `bpftool`, and links the userspace binary with `gcc`.

## Usage

```bash
sudo ./ebpf-netsec
```

### Filtering

Exclude noisy processes:

```bash
sudo ./ebpf-netsec --exclude sshd --exclude ovsdb-server --exclude python3
```

Show only specific TCP event types:

```bash
sudo ./ebpf-netsec --type CONNECT --type CLOSE
```

Available types: `CONNECT`, `OUTBOUND`, `INBOUND`, `CLOSE`.

## How TLS interception works

Without TLS, applications talk directly to the kernel's TCP stack. With TLS, an OpenSSL library sits between the application and the kernel -- and that's where the tool hooks in:

![TLS tracing overview](tls-tracing-overview.png)

The tool automatically discovers the system `libssl.so` and resolves `SSL_write` / `SSL_read` symbol offsets at startup. It uses the SSL struct's memory layout to locate the right function addresses:

![SSL struct memory layout](ssl-struct-memory-layout.png)

It then attaches uprobes to those functions:

- **`SSL_write`** -- a uprobe at entry reads the plaintext buffer before OpenSSL encrypts it.
- **`SSL_read`** -- a uprobe at entry saves the buffer pointer; a uretprobe at return reads the now-filled plaintext after OpenSSL decrypts it.

The interception happens inside the process's address space at the OpenSSL API boundary. No MITM proxy, no certificate manipulation. The wire data stays encrypted.

### Limitations

- Only intercepts processes that dynamically link against the system `libssl.so`. Applications with statically linked or bundled TLS (Node.js, Go, Rust, Java) are not captured.
- IPv4 only. IPv6 connections are filtered out.
- TLS payload capture is capped at 4095 bytes per call.

## Project structure

```
src/
  vmlinux.h              Kernel type definitions (generated by bpftool)
  tcp_monitor.bpf.c      eBPF program: TCP connection monitoring (4 kprobes)
  tcp_monitor.h          Shared tcp_event struct
  tls_intercept.bpf.c    eBPF program: TLS plaintext interception (3 uprobes)
  tls_intercept.h        Shared tls_event struct
  main.c                 Userspace loader, event handler, CLI
Makefile                 Build configuration
```
