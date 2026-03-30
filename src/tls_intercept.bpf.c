// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tls_intercept.h"

/*
 * Per-CPU scratch buffer.  The BPF stack is limited to 512 bytes, so we
 * cannot put struct tls_event (> 4 KB) there.  A PERCPU_ARRAY gives us one
 * slot per CPU that the BPF program can use as a large temporary.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct tls_event);
} tls_heap SEC(".maps");

/*
 * SSL_read is a two-step capture: we save the (buf, num) pair on entry, then
 * read the filled buffer on return once we know the actual byte count.
 */
struct ssl_read_args {
	u64 buf_ptr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);                  /* pid_tgid */
	__type(value, struct ssl_read_args);
} ssl_read_args_map SEC(".maps");

/* Perf buffer for TLS events — separate from the TCP perf buffer. */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} tls_events SEC(".maps");

/* ------------------------------------------------------------------ helpers */

/*
 * Emit a TLS event.  Uses the per-CPU scratch so the large buf[] never
 * touches the BPF stack.  Outputs only (header + data_len) bytes so the
 * perf ring isn't flooded with zeros on short messages.
 */
static __always_inline void emit_tls(void *ctx, const void *buf,
				     int num, u8 direction)
{
	if (num <= 0)
		return;

	u32 zero = 0;
	struct tls_event *ev = bpf_map_lookup_elem(&tls_heap, &zero);
	if (!ev)
		return;

	ev->ts_ns    = bpf_ktime_get_ns();
	ev->pid      = bpf_get_current_pid_tgid() >> 32;
	ev->direction = direction;
	bpf_get_current_comm(ev->comm, sizeof(ev->comm));

	u32 len = (u32)num;
	if (len > TLS_BUF_SIZE)
		len = TLS_BUF_SIZE;
	ev->data_len = len;

	bpf_probe_read_user(ev->buf, TLS_BUF_SIZE, buf);

	bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU,
			      ev, sizeof(*ev));
}

/* ---------------------------------------------------- SSL_write (one-step) */

/*
 * SSL_write(SSL *ssl, const void *buf, int num)
 * buf contains plaintext BEFORE encryption — readable at uprobe entry.
 */
SEC("uprobe/SSL_write")
int BPF_KPROBE(ssl_write_enter, void *ssl, const void *buf, int num)
{
	emit_tls(ctx, buf, num, TLS_WRITE);
	return 0;
}

/* ----------------------------------------------------- SSL_read (two-step) */

/*
 * Entry: save buf pointer keyed by pid_tgid.
 * SSL_read(SSL *ssl, void *buf, int num)
 * buf is only filled after the function returns.
 */
SEC("uprobe/SSL_read")
int BPF_KPROBE(ssl_read_enter, void *ssl, void *buf, int num)
{
	if (num <= 0)
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct ssl_read_args args = { .buf_ptr = (u64)buf };
	bpf_map_update_elem(&ssl_read_args_map, &pid_tgid, &args, BPF_ANY);
	return 0;
}

/*
 * Return: the return value is the actual bytes read.  Retrieve the saved buf
 * pointer and capture the now-filled plaintext.
 */
SEC("uretprobe/SSL_read")
int BPF_KRETPROBE(ssl_read_exit)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();

	struct ssl_read_args *args =
		bpf_map_lookup_elem(&ssl_read_args_map, &pid_tgid);
	if (!args)
		return 0;

	long ret = PT_REGS_RC(ctx);
	bpf_map_delete_elem(&ssl_read_args_map, &pid_tgid);

	if (ret <= 0)
		return 0;

	emit_tls(ctx, (void *)args->buf_ptr, (int)ret, TLS_READ);
	return 0;
}

