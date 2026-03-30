#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <ctype.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <ncurses.h>
#include <bpf/libbpf.h>
#include "tcp_monitor.skel.h"
#include "tcp_monitor.h"
#include "tls_intercept.skel.h"
#include "tls_intercept.h"

#define MAX_EXCLUDES 32

struct config {
	const char *exclude[MAX_EXCLUDES];
	int n_excludes;
	unsigned int type_mask;   /* bitmask of allowed event_type values; 0 = show all */
	FILE *export_fp;          /* NULL = no export */
	int tui;                  /* 1 = ncurses TUI active */
};

static volatile int running = 1;

static int libbpf_print_stderr(enum libbpf_print_level level,
				const char *fmt, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, fmt, args);
}

static void sig_handler(int sig)
{
	(void)sig;
	running = 0;
}

/* ── Container detection ─────────────────────────────────────────────────── */

#define CGCACHE_SLOTS 4096

struct cgcache_entry {
	__u32 pid;
	char  id[13];
};

static struct cgcache_entry cgcache[CGCACHE_SLOTS];

static int parse_cgroup_line(const char *line, char out[13])
{
	static const char *markers[] = { "/docker/", "docker-", NULL };

	for (int m = 0; markers[m]; m++) {
		const char *p = strstr(line, markers[m]);
		if (!p)
			continue;
		p += strlen(markers[m]);

		int n = 0;
		while (isxdigit((unsigned char)p[n]))
			n++;
		if (n < 12)
			continue;

		memcpy(out, p, 12);
		out[12] = '\0';
		return 1;
	}
	return 0;
}

static const char *get_container_id(__u32 pid)
{
	struct cgcache_entry *e = &cgcache[pid % CGCACHE_SLOTS];
	if (e->pid == pid)
		return e->id;

	e->pid = pid;
	strcpy(e->id, "host");

	char path[32];
	snprintf(path, sizeof(path), "/proc/%u/cgroup", pid);
	FILE *f = fopen(path, "r");
	if (!f)
		return e->id;

	char line[256];
	while (fgets(line, sizeof(line), f)) {
		if (parse_cgroup_line(line, e->id))
			break;
	}
	fclose(f);
	return e->id;
}

static void cgcache_evict(__u32 pid)
{
	struct cgcache_entry *e = &cgcache[pid % CGCACHE_SLOTS];
	if (e->pid == pid)
		e->pid = 0;
}

/* ── TLS plaintext preview cache ─────────────────────────────────────────── */

#define TLS_PREV_SLOTS 4096

struct tls_prev {
	__u32 pid;
	char  write[121];
	char  read[121];
};

static struct tls_prev tls_prev_cache[TLS_PREV_SLOTS];

static void tls_prev_set(__u32 pid, __u8 direction, const char *preview)
{
	struct tls_prev *e = &tls_prev_cache[pid % TLS_PREV_SLOTS];
	e->pid = pid;
	char *dst = (direction == TLS_WRITE) ? e->write : e->read;
	strncpy(dst, preview, 120);
	dst[120] = '\0';
}

static const char *tls_prev_get(__u32 pid, __u8 direction)
{
	struct tls_prev *e = &tls_prev_cache[pid % TLS_PREV_SLOTS];
	if (e->pid != pid)
		return NULL;
	const char *p = (direction == TLS_WRITE) ? e->write : e->read;
	return p[0] ? p : NULL;
}

/* ── DNS QNAME parser ────────────────────────────────────────────────────── */

static int parse_dns_qname(const __u8 *payload, __u16 payload_len,
			    char *out, size_t out_sz)
{
	if (payload_len < 13 || out_sz < 2)
		return -1;

	size_t i = 12;   /* skip the 12-byte DNS header */
	size_t d = 0;

	while (i < payload_len && d < out_sz - 1) {
		__u8 label_len = payload[i++];

		if (label_len == 0)
			break;

		if ((label_len & 0xC0) == 0xC0)
			break;

		if (d > 0 && d < out_sz - 1)
			out[d++] = '.';

		for (__u8 j = 0; j < label_len && i < payload_len && d < out_sz - 1; j++)
			out[d++] = (char)payload[i++];
	}

	out[d] = '\0';
	return (int)d;
}

/* ── JSON export ─────────────────────────────────────────────────────────── */

static void json_str_escape(const char *in, char *out, size_t out_sz)
{
	size_t j = 0;
	for (size_t i = 0; in[i] && j + 1 < out_sz; i++) {
		unsigned char c = (unsigned char)in[i];
		if ((c == '"' || c == '\\') && j + 2 < out_sz) {
			out[j++] = '\\';
			out[j++] = (char)c;
		} else if (c < 0x20 || c == 0x7f) {
			out[j++] = '?';
		} else {
			out[j++] = (char)c;
		}
	}
	out[j] = '\0';
}

static void export_event(FILE *fp,
			  const char *comm, __u32 pid, const char *container,
			  const char *src_ip, __u16 sport,
			  const char *dst_ip, __u16 dport,
			  __u64 bytes, const char *type_str,
			  const char *tls_preview,
			  const char *domain)
{
	time_t now = time(NULL);
	struct tm *tm = gmtime(&now);
	char ts[32];
	strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", tm);

	char comm_esc[64];
	json_str_escape(comm, comm_esc, sizeof(comm_esc));

	fprintf(fp,
		"{\"timestamp\":\"%s\","
		"\"pid\":%u,"
		"\"comm\":\"%s\","
		"\"container_id\":\"%s\","
		"\"src_ip\":\"%s\","
		"\"src_port\":%u,"
		"\"dst_ip\":\"%s\","
		"\"dst_port\":%u,"
		"\"bytes\":%llu,"
		"\"event_type\":\"%s\"",
		ts, pid, comm_esc, container,
		src_ip, (unsigned)sport,
		dst_ip, (unsigned)dport,
		(unsigned long long)bytes, type_str);

	if (tls_preview && tls_preview[0]) {
		char prev_esc[256];
		json_str_escape(tls_preview, prev_esc, sizeof(prev_esc));
		fprintf(fp, ",\"plaintext_preview\":\"%s\"", prev_esc);
	}

	if (domain && domain[0]) {
		char domain_esc[256];
		json_str_escape(domain, domain_esc, sizeof(domain_esc));
		fprintf(fp, ",\"domain\":\"%s\"", domain_esc);
	}

	fprintf(fp, "}\n");
	fflush(fp);
}

/* ── TUI ─────────────────────────────────────────────────────────────────── */

#define TUI_RING_SIZE 1000

struct tui_row {
	char   timebuf[9];
	char   comm[TASK_COMM_LEN + 1];
	__u32  pid;
	char   container[14];
	char   src[22];
	char   dst[22];
	__u64  bytes;
	__u8   type;        /* event_type */
	char   extra[270];  /* DNS domain name */
};

struct tui_state {
	struct tui_row ring[TUI_RING_SIZE];
	int  head;    /* next write slot */
	int  filled;  /* valid slots (capped at TUI_RING_SIZE) */
	long total;   /* total events ever received */
	int  active;  /* open connection count */
	int  paused;
	int  filter;  /* 0=all, 1=OUTBOUND only, 2=INBOUND only */
};

static struct tui_state g_tui;

#define CP_HEADER   1
#define CP_CONNECT  2
#define CP_OUTBOUND 3
#define CP_INBOUND  4
#define CP_CLOSE    5
#define CP_DNS      6
#define CP_FOOTER   7
#define CP_COL_HDR  8

static void tui_init(void)
{
	initscr();
	cbreak();
	noecho();
	keypad(stdscr, TRUE);
	nodelay(stdscr, TRUE);
	curs_set(0);

	if (has_colors()) {
		start_color();
		use_default_colors();
		init_pair(CP_HEADER,   COLOR_WHITE,  COLOR_BLUE);
		init_pair(CP_CONNECT,  COLOR_CYAN,   -1);
		init_pair(CP_OUTBOUND, COLOR_GREEN,  -1);
		init_pair(CP_INBOUND,  COLOR_YELLOW, -1);
		init_pair(CP_CLOSE,    COLOR_RED,    -1);
		init_pair(CP_DNS,      COLOR_MAGENTA, -1);
		init_pair(CP_FOOTER,   COLOR_BLACK,  COLOR_WHITE);
		init_pair(CP_COL_HDR,  COLOR_WHITE,  COLOR_BLACK);
	}
}

static void tui_cleanup(void)
{
	endwin();
}

static void tui_push(const struct tui_row *row)
{
	if (g_tui.paused)
		return;
	g_tui.ring[g_tui.head] = *row;
	g_tui.head = (g_tui.head + 1) % TUI_RING_SIZE;
	if (g_tui.filled < TUI_RING_SIZE)
		g_tui.filled++;
	g_tui.total++;
}

static const char *filter_label(int f)
{
	switch (f) {
	case 1:  return "OUTBOUND";
	case 2:  return "INBOUND";
	default: return "ALL";
	}
}

static void tui_draw(void)
{
	int rows, cols;
	getmaxyx(stdscr, rows, cols);

	/* ── Header bar ── */
	attron(COLOR_PAIR(CP_HEADER) | A_BOLD);
	mvhline(0, 0, ' ', cols);
	mvprintw(0, 0, " ebpf-netsec   Events: %-8ld  Active: %d%s",
		 g_tui.total, g_tui.active,
		 g_tui.paused ? "   [PAUSED]" : "");
	attroff(COLOR_PAIR(CP_HEADER) | A_BOLD);

	/* ── Column header ── */
	attron(COLOR_PAIR(CP_COL_HDR) | A_BOLD);
	mvhline(1, 0, ' ', cols);
	mvprintw(1, 0, "%-8s  %-16s  %-6s  %-13s  %-21s  %-21s  %-10s  %s",
		 "TIME", "COMM", "PID", "CONTAINER", "SRC", "DST", "BYTES", "TYPE");
	attroff(COLOR_PAIR(CP_COL_HDR) | A_BOLD);

	/* ── Event rows ── */
	int display_rows = rows - 3;  /* header + col-hdr + footer */
	if (display_rows < 1)
		goto footer;

	/* Collect up to display_rows matching events, newest-first */
	int indices[TUI_RING_SIZE];
	int n = 0;

	for (int i = 0; i < g_tui.filled && n < display_rows; i++) {
		int idx = ((g_tui.head - 1 - i) % TUI_RING_SIZE + TUI_RING_SIZE)
			  % TUI_RING_SIZE;
		const struct tui_row *r = &g_tui.ring[idx];

		if (g_tui.filter == 1 && r->type != EVENT_TX)
			continue;
		if (g_tui.filter == 2 && r->type != EVENT_RX)
			continue;

		indices[n++] = idx;
	}

	/* Clear event area */
	for (int row = 2; row < rows - 1; row++) {
		move(row, 0);
		clrtoeol();
	}

	/* Render: indices[0] is newest → bottom of screen */
	for (int i = 0; i < n; i++) {
		int scr_row = rows - 2 - i;
		if (scr_row < 2)
			break;

		const struct tui_row *r = &g_tui.ring[indices[i]];

		int cp;
		const char *type_str;
		switch (r->type) {
		case EVENT_CONNECT:   cp = CP_CONNECT;  type_str = "CONNECT";   break;
		case EVENT_TX:        cp = CP_OUTBOUND; type_str = "OUTBOUND";  break;
		case EVENT_RX:        cp = CP_INBOUND;  type_str = "INBOUND";   break;
		case EVENT_CLOSE:     cp = CP_CLOSE;    type_str = "CLOSE";     break;
		case EVENT_DNS_QUERY: cp = CP_DNS;      type_str = NULL;        break;
		default:              cp = 0;           type_str = "?";         break;
		}

		move(scr_row, 0);
		attron(COLOR_PAIR(cp));
		if (r->type == EVENT_DNS_QUERY) {
			printw("%-8s  %-16s  %-6u  %-13s  %-21s  %-21s  %-10s  DNS_QUERY %s",
			       r->timebuf, r->comm, r->pid, r->container,
			       r->src, r->dst, "", r->extra);
		} else {
			printw("%-8s  %-16s  %-6u  %-13s  %-21s  %-21s  %-10llu  %s",
			       r->timebuf, r->comm, r->pid, r->container,
			       r->src, r->dst,
			       (unsigned long long)r->bytes, type_str);
		}
		attroff(COLOR_PAIR(cp));
	}

footer:
	/* ── Footer ── */
	attron(COLOR_PAIR(CP_FOOTER));
	mvhline(rows - 1, 0, ' ', cols);
	mvprintw(rows - 1, 0,
		 " [q] quit  [p] %-6s  [f] filter: %s",
		 g_tui.paused ? "resume" : "pause",
		 filter_label(g_tui.filter));
	attroff(COLOR_PAIR(CP_FOOTER));

	refresh();
}

/* ── Non-TUI output ──────────────────────────────────────────────────────── */

static void print_header(void)
{
	printf("%-8s  %-16s  %-6s  %-13s  %-21s  %-21s  %-10s  %s\n",
	       "TIME", "COMM", "PID", "CONTAINER", "SRC", "DST", "BYTES", "TYPE");
	printf("%-8s  %-16s  %-6s  %-13s  %-21s  %-21s  %-10s  %s\n",
	       "--------", "----------------", "------", "-------------",
	       "---------------------", "---------------------",
	       "----------", "-------");
}

/* ── Event handlers ──────────────────────────────────────────────────────── */

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

	const char *container = get_container_id(ev->pid);

	/* ── DNS event ── */
	if (ev->type == EVENT_DNS_QUERY) {
		char domain[256] = {};
		parse_dns_qname(ev->dns_payload, ev->dns_payload_len,
				domain, sizeof(domain));

		char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &ev->saddr, src_ip, sizeof(src_ip));
		inet_ntop(AF_INET, &ev->daddr, dst_ip, sizeof(dst_ip));

		char src_buf[22], dst_buf[22];
		snprintf(src_buf, sizeof(src_buf), "%s:%-5u", src_ip, ev->sport);
		snprintf(dst_buf, sizeof(dst_buf), "%s:%-5u", dst_ip, ev->dport);

		if (cfg->tui) {
			time_t now = time(NULL);
			struct tm *tm = localtime(&now);
			struct tui_row row = {};
			strftime(row.timebuf, sizeof(row.timebuf), "%H:%M:%S", tm);
			strncpy(row.comm, (char *)ev->comm, TASK_COMM_LEN);
			row.pid = ev->pid;
			strncpy(row.container, container, sizeof(row.container) - 1);
			snprintf(row.src, sizeof(row.src), "%s", src_buf);
			snprintf(row.dst, sizeof(row.dst), "%s", dst_buf);
			row.type = EVENT_DNS_QUERY;
			strncpy(row.extra, domain, sizeof(row.extra) - 1);
			tui_push(&row);
		} else {
			time_t now = time(NULL);
			struct tm *tm = localtime(&now);
			char timebuf[9];
			strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tm);

			char type_buf[270];
			snprintf(type_buf, sizeof(type_buf), "DNS_QUERY %s", domain);

			printf("%-8s  %-16s  %-6u  %-13s  %-21s  %-21s  %-10s  %s\n",
			       timebuf, (char *)ev->comm, ev->pid, container,
			       src_buf, dst_buf, "", type_buf);
		}

		if (cfg->export_fp)
			export_event(cfg->export_fp,
				     (char *)ev->comm, ev->pid, container,
				     src_ip, ev->sport, dst_ip, ev->dport,
				     0, "DNS_QUERY", NULL, domain);
		return;
	}

	/* ── TCP event ── */
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
	default:            type_str = "?";        break;
	}

	if (cfg->tui) {
		time_t now = time(NULL);
		struct tm *tm = localtime(&now);
		struct tui_row row = {};
		strftime(row.timebuf, sizeof(row.timebuf), "%H:%M:%S", tm);
		strncpy(row.comm, (char *)ev->comm, TASK_COMM_LEN);
		row.pid = ev->pid;
		strncpy(row.container, container, sizeof(row.container) - 1);
		snprintf(row.src, sizeof(row.src), "%s", src);
		snprintf(row.dst, sizeof(row.dst), "%s", dst);
		row.bytes = ev->bytes;
		row.type  = ev->type;

		if (ev->type == EVENT_CONNECT)
			g_tui.active++;
		else if (ev->type == EVENT_CLOSE && g_tui.active > 0)
			g_tui.active--;

		tui_push(&row);
	} else {
		time_t now = time(NULL);
		struct tm *tm = localtime(&now);
		char timebuf[9];
		strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tm);

		printf("%-8s  %-16s  %-6u  %-13s  %-21s  %-21s  %-10llu  %s\n",
		       timebuf, (char *)ev->comm, ev->pid, container,
		       src, dst, (unsigned long long)ev->bytes, type_str);
	}

	if (cfg->export_fp) {
		__u8 tls_dir = (ev->type == EVENT_TX) ? TLS_WRITE : TLS_READ;
		const char *tls_preview = tls_prev_get(ev->pid, tls_dir);
		export_event(cfg->export_fp,
			     (char *)ev->comm, ev->pid, container,
			     src_ip, ev->sport, dst_ip, ev->dport,
			     ev->bytes, type_str, tls_preview, NULL);
	}

	if (ev->type == EVENT_CLOSE)
		cgcache_evict(ev->pid);
}

static void handle_lost(void *ctx, int cpu, __u64 lost_cnt)
{
	struct config *cfg = ctx;
	if (!cfg->tui)
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

	tls_prev_set(ev->pid, ev->direction, preview);

	if (!cfg->tui) {
		const char *container = get_container_id(ev->pid);
		const char *dir = (ev->direction == TLS_WRITE) ? "OUTBOUND" : "INBOUND";
		printf("TLS  %-16s  %-6u  %-13s  %-8s  %4u bytes  %s\n",
		       (char *)ev->comm, ev->pid, container, dir, ev->data_len, preview);
	}
}

static void handle_tls_lost(void *ctx, int cpu, __u64 lost_cnt)
{
	struct config *cfg = ctx;
	if (!cfg->tui)
		fprintf(stderr, "Warning: lost %llu TLS events on CPU %d\n",
			(unsigned long long)lost_cnt, cpu);
}

/* ── Symbol resolution ───────────────────────────────────────────────────── */

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

/* ── Argument parsing ────────────────────────────────────────────────────── */

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--exclude <comm>] [--type <type>] [--export <file>] [--tui]\n",
		prog);
	fprintf(stderr, "  --exclude <comm>   Drop events from process named <comm> (repeatable)\n");
	fprintf(stderr, "  --type <type>      Show only this event type (repeatable)\n");
	fprintf(stderr, "                     Types: CONNECT, OUTBOUND, INBOUND, CLOSE\n");
	fprintf(stderr, "  --export <file>    Append events as JSON lines to <file>\n");
	fprintf(stderr, "  --tui              Interactive ncurses TUI (q=quit, p=pause, f=filter)\n");
}

static int parse_type(const char *s)
{
	if (strcmp(s, "CONNECT")  == 0) return EVENT_CONNECT;
	if (strcmp(s, "OUTBOUND") == 0) return EVENT_TX;
	if (strcmp(s, "INBOUND")  == 0) return EVENT_RX;
	if (strcmp(s, "CLOSE")    == 0) return EVENT_CLOSE;
	return -1;
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
	struct config cfg = {
		.exclude    = { "ovsdb-server" },
		.n_excludes = 1,
	};
	struct tcp_monitor_bpf   *tcp_skel = NULL;
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
				fprintf(stderr,
					"Unknown type '%s'. Valid: CONNECT, OUTBOUND, INBOUND, CLOSE\n",
					argv[i]);
				return 1;
			}
			cfg.type_mask |= (1u << t);
		} else if (strcmp(argv[i], "--export") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr, "--export requires a filename\n");
				return 1;
			}
			cfg.export_fp = fopen(argv[++i], "a");
			if (!cfg.export_fp) {
				fprintf(stderr, "Cannot open export file '%s': %s\n",
					argv[i], strerror(errno));
				return 1;
			}
		} else if (strcmp(argv[i], "--tui") == 0) {
			cfg.tui = 1;
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

	libbpf_set_print(libbpf_print_stderr);

	/* ── TCP monitor ── */
	tcp_skel = tcp_monitor_bpf__open_and_load();
	libbpf_set_print(NULL);
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

	/* ── TLS interceptor ── */
	libbpf_set_print(libbpf_print_stderr);
	tls_skel = tls_intercept_bpf__open_and_load();
	libbpf_set_print(NULL);

	if (!tls_skel) {
		fprintf(stderr, "[TLS] FAILED to load BPF skeleton — "
			"continuing without TLS interception\n");
		goto run;
	}

	char libssl[512] = {};
	if (find_libssl(libssl, sizeof(libssl)) < 0) {
		fprintf(stderr, "[TLS] FAILED: libssl.so not found under /usr/lib\n");
		goto run;
	}

	size_t ssl_write_off = find_sym_offset(libssl, "SSL_write");
	size_t ssl_read_off  = find_sym_offset(libssl, "SSL_read");

	if (!ssl_write_off || !ssl_read_off) {
		fprintf(stderr, "[TLS] FAILED: could not resolve symbol offsets\n");
		goto run;
	}

	tls_links[0] = bpf_program__attach_uprobe(
		tls_skel->progs.ssl_write_enter, false, -1, libssl, ssl_write_off);
	tls_links[1] = bpf_program__attach_uprobe(
		tls_skel->progs.ssl_read_enter, false, -1, libssl, ssl_read_off);
	tls_links[2] = bpf_program__attach_uprobe(
		tls_skel->progs.ssl_read_exit, true, -1, libssl, ssl_read_off);

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
	if (!pb_tls)
		fprintf(stderr, "[TLS] FAILED to create perf buffer (%s) — "
			"continuing without TLS interception\n", strerror(errno));

run:
	if (cfg.tui)
		tui_init();
	else
		print_header();

	while (running) {
		/* Poll TLS first: SSL_write fires before tcp_sendmsg, so the
		 * preview is cached before the TCP OUTBOUND event is processed. */
		if (pb_tls) {
			err = perf_buffer__poll(pb_tls, 0);
			if (err < 0 && err != -EINTR) {
				if (cfg.tui) tui_cleanup();
				fprintf(stderr, "TLS perf buffer poll error: %d\n", err);
				break;
			}
		}

		err = perf_buffer__poll(pb_tcp, cfg.tui ? 0 : 50);
		if (err < 0 && err != -EINTR) {
			if (cfg.tui) tui_cleanup();
			fprintf(stderr, "TCP perf buffer poll error: %d\n", err);
			break;
		}
		err = 0;

		if (cfg.tui) {
			tui_draw();

			int ch = getch();
			switch (ch) {
			case 'q': case 'Q':
				running = 0;
				break;
			case 'p': case 'P':
				g_tui.paused = !g_tui.paused;
				break;
			case 'f': case 'F':
				g_tui.filter = (g_tui.filter + 1) % 3;
				break;
			}

			/* ~50ms sleep to avoid spinning at 100% CPU */
			struct timespec ts = { .tv_nsec = 50000000L };
			nanosleep(&ts, NULL);
		}
	}

	if (cfg.tui)
		tui_cleanup();

	if (pb_tls)
		perf_buffer__free(pb_tls);
	perf_buffer__free(pb_tcp);
cleanup:
	if (cfg.export_fp)
		fclose(cfg.export_fp);
	for (int i = 0; i < 3; i++)
		if (tls_links[i])
			bpf_link__destroy(tls_links[i]);
	if (tls_skel)
		tls_intercept_bpf__destroy(tls_skel);
	tcp_monitor_bpf__destroy(tcp_skel);
	return err;
}
