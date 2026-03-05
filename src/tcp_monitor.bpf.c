#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "tcp_monitor.h"

#define AF_INET 2

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline int fill_event(struct tcp_event *ev, struct sock *sk,
				      u64 bytes, u8 type)
{
	u16 family;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET)
		return -1;

	ev->ts_ns = bpf_ktime_get_ns();
	ev->pid   = bpf_get_current_pid_tgid() >> 32;
	ev->bytes = bytes;
	ev->type  = type;

	bpf_get_current_comm(ev->comm, sizeof(ev->comm));

	ev->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	ev->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	ev->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	ev->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

	return 0;
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(tcp_connect, struct sock *sk)
{
	struct tcp_event ev = {};

	if (fill_event(&ev, sk, 0, EVENT_CONNECT) < 0)
		return 0;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
	return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	struct tcp_event ev = {};

	if (fill_event(&ev, sk, size, EVENT_TX) < 0)
		return 0;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
	return 0;
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(tcp_recvmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
	struct tcp_event ev = {};

	if (fill_event(&ev, sk, len, EVENT_RX) < 0)
		return 0;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
	return 0;
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(tcp_close, struct sock *sk, long timeout)
{
	struct tcp_event ev = {};

	if (fill_event(&ev, sk, 0, EVENT_CLOSE) < 0)
		return 0;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
