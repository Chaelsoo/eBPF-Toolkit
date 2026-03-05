#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include "tcp_monitor.skel.h"
#include "tcp_monitor.h"
#include "tls_intercept.skel.h"
#include "tls_intercept.h"

#define MAX_EXCLUDES 32

struct config {
	const char *exclude[MAX_EXCLUDES];
	int n_excludes;
	unsigned int type_mask;
};

static volatile int running = 1;

static int libbpf_print_stderr(enum libbpf_print_level level,
				const char *fmt, va_list args)
{
	(void)level;
	return vfprintf(stderr, fmt, args);
}

static void sig_handler(int sig)
{
	(void)sig;
	running = 0;
}

static void print_header(void)
{
	printf("%-8s  %-16s  %-6s  %-21s  %-21s  %-10s  %s\n",
	       "TIME", "COMM", "PID", "SRC", "DST", "BYTES", "TYPE");
	printf("%-8s  %-16s  %-6s  %-21s  %-21s  %-10s  %s\n",
	       "--------", "----------------", "------",
	       "---------------------", "---------------------",
	       "----------", "-------");
}

static void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
	(void)cpu; (void)size;
	struct config *cfg = ctx;
	struct tcp_event *ev = data;

	if (cfg->type_mask && !(cfg->type_mask & (1u << ev->type)))
		return;

	for (int i = 0; i < cfg->n_excludes; i++) {
		if (strncmp((char *)ev->comm, cfg->exclude[i], TASK_COMM_LEN) == 0)
			return;
	}

	time_t now = time(NULL);
	struct tm *tm = localtime(&now);
	char timebuf[9];
	strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tm);

	char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &ev->saddr, src_ip, sizeof(src_ip));
	inet_ntop(AF_INET, &ev->daddr, dst_ip, sizeof(dst_ip));

	char src[22], dst[22];
	snprintf(src, sizeof(src), "%s:%-5u", src_ip, ev->sport);
	snprintf(dst, sizeof(dst), "%s:%-5u", dst_ip, ev->dport);

	const char *type_str;
	switch (ev->type) {
	case EVENT_CONNECT: type_str = "CONNECT";  break;
	case EVENT_TX:      type_str = "OUTBOUND"; break;
	case EVENT_RX:      type_str = "INBOUND";  break;
	case EVENT_CLOSE:   type_str = "CLOSE";    break;
	default:            type_str = "?";       break;
	}

	printf("%-8s  %-16s  %-6u  %-21s  %-21s  %-10llu  %s\n",
	       timebuf,
	       (char *)ev->comm,
	       ev->pid,
	       src, dst,
	       (unsigned long long)ev->bytes,
	       type_str);
}

static void handle_lost(void *ctx, int cpu, __u64 lost_cnt)
{
	(void)ctx;
	fprintf(stderr, "Warning: lost %llu events on CPU %d\n",
		(unsigned long long)lost_cnt, cpu);
}

static void handle_tls_event(void *ctx, int cpu, void *data, __u32 size)
{
	(void)cpu; (void)size;
	struct config *cfg = ctx;
	struct tls_event *ev = data;

	for (int i = 0; i < cfg->n_excludes; i++) {
		if (strncmp((char *)ev->comm, cfg->exclude[i], TASK_COMM_LEN) == 0)
			return;
	}

	char preview[121];
	size_t n = ev->data_len < 120 ? ev->data_len : 120;
	memcpy(preview, ev->buf, n);
	for (size_t i = 0; i < n; i++) {
		unsigned char c = (unsigned char)preview[i];
		if (c < 0x20 || c > 0x7e)
			preview[i] = '.';
	}
	preview[n] = '\0';

	const char *dir = (ev->direction == TLS_WRITE) ? "OUTBOUND" : "INBOUND";
	printf("TLS  %-16s  %-6u  %-8s  %4u bytes  %s\n",
	       (char *)ev->comm, ev->pid, dir, ev->data_len, preview);
}

static void handle_tls_lost(void *ctx, int cpu, __u64 lost_cnt)
{
	(void)ctx;
	fprintf(stderr, "Warning: lost %llu TLS events on CPU %d\n",
		(unsigned long long)lost_cnt, cpu);
}

/*
 * Return the file offset of <sym> in <lib>.
 * Uses awk to match the exact symbol name (handles versioned symbols like
 * SSL_write@@OPENSSL_3.0.0 without matching SSL_write_ex or SSL_write_early_data).
 */
static size_t find_sym_offset(const char *lib, const char *sym)
{
	char cmd[512];
	snprintf(cmd, sizeof(cmd),
		 "nm -D '%s' 2>/dev/null | "
		 "awk '($3==\"%s\" || index($3,\"%s@@\")==1) {print $1; exit}'",
		 lib, sym, sym);
	FILE *fp = popen(cmd, "r");
	if (!fp)
		return 0;
	size_t off = 0;
	char line[64];
	if (fgets(line, sizeof(line), fp))
		off = (size_t)strtoul(line, NULL, 16);
	pclose(fp);
	return off;
}

static int find_libssl(char *out, size_t out_sz)
{
	FILE *fp = popen(
		"find /usr/lib -name 'libssl.so*' -type f 2>/dev/null"
		" | sort | tail -1", "r");
	if (!fp)
		return -1;
	if (!fgets(out, out_sz, fp)) {
		pclose(fp);
		return -1;
	}
	pclose(fp);
	out[strcspn(out, "\n")] = '\0';
	return out[0] ? 0 : -1;
}

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [--exclude <comm>] [--type <type>] ...\n", prog);
	fprintf(stderr, "  --exclude <comm>   Drop events from process named <comm> (repeatable)\n");
	fprintf(stderr, "  --type <type>      Show only this event type (repeatable)\n");
	fprintf(stderr, "                     Types: CONNECT, OUTBOUND, INBOUND, CLOSE\n");
}

static int parse_type(const char *s)
{
	if (strcmp(s, "CONNECT")  == 0) return EVENT_CONNECT;
	if (strcmp(s, "OUTBOUND") == 0) return EVENT_TX;
	if (strcmp(s, "INBOUND")  == 0) return EVENT_RX;
	if (strcmp(s, "CLOSE")    == 0) return EVENT_CLOSE;
	return -1;
}

int main(int argc, char **argv)
{
	struct config cfg = {
		.exclude    = { "ovsdb-server" },
		.n_excludes = 1,
	};
	struct tcp_monitor_bpf  *tcp_skel = NULL;
	struct tls_intercept_bpf *tls_skel = NULL;
	struct perf_buffer *pb_tcp = NULL, *pb_tls = NULL;
	struct bpf_link *tls_links[3] = {};
	int err = 0;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--exclude") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr, "--exclude requires an argument\n");
				return 1;
			}
			if (cfg.n_excludes >= MAX_EXCLUDES) {
				fprintf(stderr, "Too many --exclude filters (max %d)\n", MAX_EXCLUDES);
				return 1;
			}
			cfg.exclude[cfg.n_excludes++] = argv[++i];
		} else if (strcmp(argv[i], "--type") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr, "--type requires an argument\n");
				return 1;
			}
			int t = parse_type(argv[++i]);
			if (t < 0) {
				fprintf(stderr, "Unknown type '%s'. Valid: CONNECT, OUTBOUND, INBOUND, CLOSE\n", argv[i]);
				return 1;
			}
			cfg.type_mask |= (1u << t);
		} else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
			usage(argv[0]);
			return 0;
		} else {
			fprintf(stderr, "Unknown argument: %s\n", argv[i]);
			usage(argv[0]);
			return 1;
		}
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	libbpf_set_print(NULL);

	tcp_skel = tcp_monitor_bpf__open_and_load();
	if (!tcp_skel) {
		fprintf(stderr, "Failed to open/load TCP BPF skeleton\n");
		return 1;
	}
	err = tcp_monitor_bpf__attach(tcp_skel);
	if (err) {
		fprintf(stderr, "Failed to attach TCP BPF programs: %d\n", err);
		goto cleanup;
	}

	struct perf_buffer_opts tcp_pb_opts = {
		.sample_cb = handle_event,
		.lost_cb   = handle_lost,
		.ctx       = &cfg,
	};
	pb_tcp = perf_buffer__new(bpf_map__fd(tcp_skel->maps.events), 16,
				  &tcp_pb_opts);
	if (!pb_tcp) {
		fprintf(stderr, "Failed to create TCP perf buffer\n");
		err = 1;
		goto cleanup;
	}

	fprintf(stderr, "[TLS] Loading BPF programs...\n");


	libbpf_set_print(libbpf_print_stderr);
	tls_skel = tls_intercept_bpf__open_and_load();
	libbpf_set_print(NULL);

	if (!tls_skel) {
		fprintf(stderr, "[TLS] FAILED to load BPF skeleton — "
			"continuing without TLS interception\n");
		goto run;
	}
	fprintf(stderr, "[TLS] BPF programs loaded OK\n");

	char libssl[512] = {};
	if (find_libssl(libssl, sizeof(libssl)) < 0) {
		fprintf(stderr, "[TLS] FAILED: libssl.so not found under /usr/lib\n");
		goto run;
	}
	fprintf(stderr, "[TLS] libssl: %s\n", libssl);

	size_t ssl_write_off = find_sym_offset(libssl, "SSL_write");
	size_t ssl_read_off  = find_sym_offset(libssl, "SSL_read");
	fprintf(stderr, "[TLS] SSL_write offset: 0x%zx\n", ssl_write_off);
	fprintf(stderr, "[TLS] SSL_read  offset: 0x%zx\n", ssl_read_off);

	if (!ssl_write_off || !ssl_read_off) {
		fprintf(stderr, "[TLS] FAILED: could not resolve symbol offsets\n");
		goto run;
	}

	tls_links[0] = bpf_program__attach_uprobe(
		tls_skel->progs.ssl_write_enter, false, -1, libssl, ssl_write_off);
	fprintf(stderr, "[TLS] uprobe  ssl_write_enter: %s%s\n",
		tls_links[0] ? "OK" : "FAILED",
		tls_links[0] ? "" : strerror(errno));

	tls_links[1] = bpf_program__attach_uprobe(
		tls_skel->progs.ssl_read_enter, false, -1, libssl, ssl_read_off);
	fprintf(stderr, "[TLS] uprobe  ssl_read_enter:  %s%s\n",
		tls_links[1] ? "OK" : "FAILED",
		tls_links[1] ? "" : strerror(errno));

	tls_links[2] = bpf_program__attach_uprobe(
		tls_skel->progs.ssl_read_exit, true, -1, libssl, ssl_read_off);
	fprintf(stderr, "[TLS] uretprobe ssl_read_exit: %s%s\n",
		tls_links[2] ? "OK" : "FAILED",
		tls_links[2] ? "" : strerror(errno));

	if (!tls_links[0] || !tls_links[1] || !tls_links[2]) {
		fprintf(stderr, "[TLS] One or more uprobes failed — "
			"continuing without TLS interception\n");
		goto run;
	}

	struct perf_buffer_opts tls_pb_opts = {
		.sample_cb = handle_tls_event,
		.lost_cb   = handle_tls_lost,
		.ctx       = &cfg,
	};
	pb_tls = perf_buffer__new(bpf_map__fd(tls_skel->maps.tls_events), 16,
				  &tls_pb_opts);
	if (!pb_tls) {
		fprintf(stderr, "[TLS] FAILED to create perf buffer (%s) — "
			"continuing without TLS interception\n", strerror(errno));
	} else {
		fprintf(stderr, "[TLS] Interception active\n");
	}

run:
	print_header();

	while (running) {
		err = perf_buffer__poll(pb_tcp, 50 /* ms */);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "TCP perf buffer poll error: %d\n", err);
			break;
		}
		if (pb_tls) {
			err = perf_buffer__poll(pb_tls, 50 /* ms */);
			if (err < 0 && err != -EINTR) {
				fprintf(stderr, "TLS perf buffer poll error: %d\n", err);
				break;
			}
		}
		err = 0;
	}

	if (pb_tls)
		perf_buffer__free(pb_tls);
	perf_buffer__free(pb_tcp);
cleanup:
	for (int i = 0; i < 3; i++)
		if (tls_links[i])
			bpf_link__destroy(tls_links[i]);
	if (tls_skel)
		tls_intercept_bpf__destroy(tls_skel);
	tcp_monitor_bpf__destroy(tcp_skel);
	return err;
}
