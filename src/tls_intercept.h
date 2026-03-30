/* tls_intercept.h — shared between BPF and userspace */
#ifndef __TLS_INTERCEPT_H
#define __TLS_INTERCEPT_H

#define TLS_BUF_SIZE 4096

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

enum tls_direction {
	TLS_WRITE = 0,   /* SSL_write: plaintext before encryption */
	TLS_READ  = 1,   /* SSL_read:  plaintext after decryption  */
};

struct tls_event {
	__u64 ts_ns;
	__u32 pid;
	__u32 data_len;          /* bytes captured in buf (≤ TLS_BUF_SIZE) */
	__u8  comm[TASK_COMM_LEN];
	__u8  direction;         /* enum tls_direction */
	__u8  pad[3];
	__u8  buf[TLS_BUF_SIZE];
};

#endif /* __TLS_INTERCEPT_H */
