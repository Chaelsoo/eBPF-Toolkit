// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "tcp_monitor.h"

/* vmlinux.h doesn't export socket family macros */
#define AF_INET 2

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

/* Fill common fields from the sock struct. Returns 0 on success, -1 to skip. */
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
	ev->sport = BPF_CORE_READ(sk, __sk_common.skc_num);          /* host order */
	ev->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport)); /* net→host */

	return 0;
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(tcp_connect, struct sock *sk)
{
	struct tcp_event ev = {};

	if (fill_event(&ev, sk, 0, EVENT_CONNECT) < 0)
		return 0;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, TCP_HDR_SIZE);
	return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	struct tcp_event ev = {};

	if (fill_event(&ev, sk, size, EVENT_TX) < 0)
		return 0;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, TCP_HDR_SIZE);
	return 0;
}

/*
 * tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, ...)
 * We capture `len` (the requested receive size) at entry.
 */
SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(tcp_recvmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
	struct tcp_event ev = {};

	if (fill_event(&ev, sk, len, EVENT_RX) < 0)
		return 0;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, TCP_HDR_SIZE);
	return 0;
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(tcp_close, struct sock *sk, long timeout)
{
	struct tcp_event ev = {};

	if (fill_event(&ev, sk, 0, EVENT_CLOSE) < 0)
		return 0;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, TCP_HDR_SIZE);
	return 0;
}

/*
 * Hook UDP sends and capture the raw DNS wire payload for port-53 traffic.
 *
 * udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
 *
 * The kernel has already copied the iovec into msg_iter before calling here,
 * but iov_base still points into userspace — use bpf_probe_read_user.
 */
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
	/* Only IPv4 port-53 traffic */
	u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET)
		return 0;

	u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (dport != 53)
		return 0;

	struct tcp_event ev = {};

	ev.ts_ns = bpf_ktime_get_ns();
	ev.pid   = bpf_get_current_pid_tgid() >> 32;
	ev.type  = EVENT_DNS_QUERY;
	ev.bytes = 0;

	bpf_get_current_comm(ev.comm, sizeof(ev.comm));

	ev.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	ev.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	ev.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	ev.dport = dport;

	/*
	 * Walk msg_iter.iov[0] to find the userspace buffer.
	 * iov_iter.iov is the first member of the union so CO-RE resolves it.
	 */
	const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.iov);
	void   *iov_base = BPF_CORE_READ(iov, iov_base);
	size_t  iov_len  = BPF_CORE_READ(iov, iov_len);

	u32 payload_len = (u32)iov_len;
	if (payload_len > DNS_PAYLOAD_MAX)
		payload_len = DNS_PAYLOAD_MAX;

	ev.dns_payload_len = (__u16)payload_len;

	bpf_probe_read_user(ev.dns_payload, DNS_PAYLOAD_MAX, iov_base);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
	return 0;
}

