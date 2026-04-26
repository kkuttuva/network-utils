// socklatency.bpf.c
// Measures send/receive turnaround time for every socket using kprobes.
// Tracks: time from tcp_sendmsg → tcp_recvmsg (request-response cycle)
// and raw send/recv latency within individual calls.

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/in.h>

// ─── Data Structures ─────────────────────────────────────────────────────────

struct sock_key_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 pid;
};

struct latency_event_t {
    u32  pid;
    u32  tid;
    u64  ts_ns;
    u64  delta_us;   // latency in microseconds
    u32  saddr;
    u32  daddr;
    u16  sport;
    u16  dport;
    u8   event_type; // 0=send, 1=recv, 2=turnaround
    char comm[16];
};

// ─── BPF Maps ─────────────────────────────────────────────────────────────────

// Tracks in-flight send timestamps: sock ptr → timestamp
BPF_HASH(send_start, u64, u64);

// Tracks last send time per socket key for turnaround measurement
BPF_HASH(last_send, struct sock_key_t, u64);

// Output ring buffer for userspace consumption
BPF_PERF_OUTPUT(events);

// Per-socket latency histograms (microseconds, log2 buckets)
BPF_HISTOGRAM(send_hist,  u64, 64);
BPF_HISTOGRAM(recv_hist,  u64, 64);
BPF_HISTOGRAM(turnaround_hist, u64, 64);

// Counters
BPF_ARRAY(counters, u64, 4); // [sends, recvs, turnarounds, errors]

// ─── Helpers ──────────────────────────────────────────────────────────────────

static inline void fill_sock_key(struct sock_key_t *key, struct sock *sk) {
    struct inet_sock *inet = inet_sk(sk);
    key->saddr = inet->inet_saddr;
    key->daddr = inet->inet_daddr;
    key->sport = inet->inet_sport;
    key->dport = inet->inet_dport;
    key->pid   = bpf_get_current_pid_tgid() >> 32;
}

static inline void incr_counter(int idx) {
    u64 *val = counters.lookup(&idx);
    if (val) (*val)++;
}

// ─── tcp_sendmsg entry: record send start time ────────────────────────────────

int trace_send_entry(struct pt_regs *ctx, struct sock *sk,
                     struct msghdr *msg, size_t size)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    u64 sk_ptr = (u64)(unsigned long)sk;

    send_start.update(&sk_ptr, &ts);

    // Record last send for turnaround tracking
    struct sock_key_t key = {};
    fill_sock_key(&key, sk);
    last_send.update(&key, &ts);

    return 0;
}

// ─── tcp_sendmsg return: compute send duration ────────────────────────────────

int trace_send_return(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u64 ts  = bpf_ktime_get_ns();

    // We can't easily recover sk here without a separate map keyed by pid_tgid
    // So we emit the send latency from trace_recv_entry instead (turnaround)
    incr_counter(0);
    return 0;
}

// ─── tcp_recvmsg entry: compute turnaround ────────────────────────────────────

int trace_recv_entry(struct pt_regs *ctx, struct sock *sk,
                     struct msghdr *msg, size_t size, int flags)
{
    u64 ts     = bpf_ktime_get_ns();
    u64 sk_ptr = (u64)(unsigned long)sk;

    // Measure send→recv turnaround
    struct sock_key_t key = {};
    fill_sock_key(&key, sk);

    u64 *send_ts = last_send.lookup(&key);
    if (send_ts && *send_ts > 0) {
        u64 delta_ns = ts - *send_ts;
        u64 delta_us = delta_ns / 1000;

        struct latency_event_t ev = {};
        bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
        ev.pid        = key.pid;
        ev.tid        = (u32)(bpf_get_current_pid_tgid() & 0xFFFFFFFF);
        ev.ts_ns      = ts;
        ev.delta_us   = delta_us;
        ev.saddr      = key.saddr;
        ev.daddr      = key.daddr;
        ev.sport      = key.sport;
        ev.dport      = key.dport;
        ev.event_type = 2; // turnaround

        events.perf_submit(ctx, &ev, sizeof(ev));
        turnaround_hist.increment(bpf_log2l(delta_us));
        incr_counter(2);

        // Reset so we don't double-count
        u64 zero = 0;
        last_send.update(&key, &zero);
    }

    return 0;
}

// ─── tcp_recvmsg return: measure recv call duration ───────────────────────────

// We track recv start separately
BPF_HASH(recv_start, u64, u64); // pid_tgid → ts

int trace_recv_start(struct pt_regs *ctx, struct sock *sk,
                     struct msghdr *msg, size_t size, int flags)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    recv_start.update(&pid_tgid, &ts);
    return 0;
}

// sock ptr storage for recv return
BPF_HASH(recv_sk, u64, u64); // pid_tgid → sk ptr

int trace_recv_entry2(struct pt_regs *ctx, struct sock *sk,
                      struct msghdr *msg, size_t size, int flags)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 sk_ptr = (u64)(unsigned long)sk;
    recv_sk.update(&pid_tgid, &sk_ptr);

    u64 ts = bpf_ktime_get_ns();
    recv_start.update(&pid_tgid, &ts);
    return 0;
}

int trace_recv_return(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u64 ts  = bpf_ktime_get_ns();

    u64 *start_ts = recv_start.lookup(&pid_tgid);
    u64 *sk_ptr   = recv_sk.lookup(&pid_tgid);
    if (!start_ts || !sk_ptr) return 0;

    u64 delta_ns = ts - *start_ts;
    u64 delta_us = delta_ns / 1000;

    struct sock *sk = (struct sock *)(unsigned long)(*sk_ptr);
    struct sock_key_t key = {};
    fill_sock_key(&key, sk);

    struct latency_event_t ev = {};
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.pid        = pid;
    ev.tid        = (u32)(pid_tgid & 0xFFFFFFFF);
    ev.ts_ns      = ts;
    ev.delta_us   = delta_us;
    ev.saddr      = key.saddr;
    ev.daddr      = key.daddr;
    ev.sport      = key.sport;
    ev.dport      = key.dport;
    ev.event_type = 1; // recv

    events.perf_submit(ctx, &ev, sizeof(ev));
    recv_hist.increment(bpf_log2l(delta_us));
    incr_counter(1);

    recv_start.delete(&pid_tgid);
    recv_sk.delete(&pid_tgid);
    return 0;
}
