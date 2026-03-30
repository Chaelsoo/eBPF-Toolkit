/* tcp_monitor.h — shared between BPF and userspace */
#ifndef __TCP_MONITOR_H
#define __TCP_MONITOR_H

#define TASK_COMM_LEN   16
#define DNS_PAYLOAD_MAX 256

enum event_type {
	EVENT_CONNECT   = 0,
	EVENT_TX        = 1,
	EVENT_RX        = 2,
	EVENT_CLOSE     = 3,
	EVENT_DNS_QUERY = 4,
};

struct tcp_event {
	__u64 ts_ns;          /* monotonic boot time from bpf_ktime_get_ns() */
	__u32 pid;
	__u32 saddr;          /* source IP, network byte order */
	__u32 daddr;          /* dest IP, network byte order */
	__u16 sport;          /* source port, host byte order */
	__u16 dport;          /* dest port, host byte order */
	__u64 bytes;
	__u8  comm[TASK_COMM_LEN];
	__u8  type;           /* enum event_type */
	__u8  pad;
	__u16 dns_payload_len; /* bytes valid in dns_payload; 0 for non-DNS */
	__u8  dns_payload[DNS_PAYLOAD_MAX]; /* raw DNS wire data (port-53 only) */
};

/*
 * Fixed header size — the part every event type sends.
 * Use __builtin_offsetof so the value is the true byte offset of dns_payload,
 * not sizeof(tcp_event) - DNS_PAYLOAD_MAX which would include trailing
 * compiler padding and give the wrong answer.
 */
#define TCP_HDR_SIZE __builtin_offsetof(struct tcp_event, dns_payload)

#endif /* __TCP_MONITOR_H */
