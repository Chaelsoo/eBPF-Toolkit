#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tls_intercept.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct tls_event);
} tls_heap SEC(".maps");

struct ssl_read_args {
	u64 buf_ptr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);                  /* pid_tgid */
	__type(value, struct ssl_read_args);
} ssl_read_args_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} tls_events SEC(".maps");

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
	if (len > TLS_BUF_SIZE - 1)
		len = TLS_BUF_SIZE - 1;

	asm volatile("" : "+r"(len));
	len &= (TLS_BUF_SIZE - 1);

	ev->data_len = len;

	bpf_probe_read_user(ev->buf, len, buf);

	u32 output_sz = sizeof(*ev) - TLS_BUF_SIZE + len;
	bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU,
			      ev, output_sz);
}

SEC("uprobe/SSL_write")
int BPF_KPROBE(ssl_write_enter, void *ssl, const void *buf, int num)
{
	emit_tls(ctx, buf, num, TLS_WRITE);
	return 0;
}

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

char LICENSE[] SEC("license") = "GPL";
