#ifndef __TCP_MONITOR_H
#define __TCP_MONITOR_H

#define TASK_COMM_LEN 16

enum event_type {
	EVENT_CONNECT = 0,
	EVENT_TX      = 1,
	EVENT_RX      = 2,
	EVENT_CLOSE   = 3,
};

struct tcp_event {
	__u64 ts_ns;
	__u32 pid;
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u64 bytes;
	__u8  comm[TASK_COMM_LEN];
	__u8  type;
	__u8  pad[7];
};

#endif
