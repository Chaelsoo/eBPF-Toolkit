#ifndef __TLS_INTERCEPT_H
#define __TLS_INTERCEPT_H

#define TLS_BUF_SIZE 4096

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

enum tls_direction {
	TLS_WRITE = 0,
	TLS_READ  = 1,
};

struct tls_event {
	__u64 ts_ns;
	__u32 pid;
	__u32 data_len;
	__u8  comm[TASK_COMM_LEN];
	__u8  direction;
	__u8  pad[3];
	__u8  buf[TLS_BUF_SIZE];
};

#endif
