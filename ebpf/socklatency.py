#!/usr/bin/env python3
# socklatency.py — eBPF Socket Send/Receive Turnaround Monitor
# Requires: python3-bpfcc (system package), root privileges
#
# Usage:
#   sudo python3 socklatency.py [options]
#   sudo python3 socklatency.py --pid 1234
#   sudo python3 socklatency.py --port 443
#   sudo python3 socklatency.py --interval 2 --top 20

import sys
import os
import argparse
import ctypes
import socket
import struct
import time
import signal
import threading
import collections
from datetime import datetime

# ─── Ensure we use the system BCC, not pip's impostor ─────────────────────────
sys.path.insert(0, "/usr/lib/python3/dist-packages")

try:
    from bcc import BPF
except ImportError:
    print("ERROR: python3-bpfcc not found.")
    print("Install with: sudo apt install python3-bpfcc bpfcc-tools")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.columns import Columns
    from rich.text import Text
    from rich.layout import Layout
    from rich.align import Align
    from rich import box
except ImportError:
    print("ERROR: 'rich' library not found.")
    print("Install with: pip3 install --break-system-packages rich")
    sys.exit(1)

# ─── BPF Program Source ────────────────────────────────────────────────────────

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/tcp.h>

/* ── Structures ── */

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
    u64  delta_us;
    u32  saddr;
    u32  daddr;
    u16  sport;
    u16  dport;
    u8   event_type;   /* 0=send, 1=recv, 2=turnaround */
    char comm[16];
};

/* ── Maps ── */

BPF_HASH(last_send,   struct sock_key_t, u64);
BPF_HASH(recv_start,  u64, u64);
BPF_HASH(recv_sk_map, u64, u64);
BPF_PERF_OUTPUT(events);
BPF_HISTOGRAM(send_lat_hist,        u64, 64);
BPF_HISTOGRAM(recv_lat_hist,        u64, 64);
BPF_HISTOGRAM(turnaround_lat_hist,  u64, 64);

/* ── Helpers ── */

static inline void fill_sock_key(struct sock_key_t *key, struct sock *sk) {
    struct inet_sock *inet = inet_sk(sk);
    bpf_probe_read_kernel(&key->saddr, sizeof(key->saddr), &inet->inet_saddr);
    bpf_probe_read_kernel(&key->daddr, sizeof(key->daddr), &inet->inet_daddr);
    bpf_probe_read_kernel(&key->sport, sizeof(key->sport), &inet->inet_sport);
    bpf_probe_read_kernel(&key->dport, sizeof(key->dport), &inet->inet_dport);
    key->pid = bpf_get_current_pid_tgid() >> 32;
}

/* ── tcp_sendmsg: record send timestamp ── */

int trace_send_entry(struct pt_regs *ctx, struct sock *sk,
                     struct msghdr *msg, size_t size)
{
    u64 ts = bpf_ktime_get_ns();
    struct sock_key_t key = {};
    fill_sock_key(&key, sk);
    last_send.update(&key, &ts);
    return 0;
}

/* ── tcp_recvmsg: entry — measure turnaround & start recv timer ── */

int trace_recv_entry(struct pt_regs *ctx, struct sock *sk,
                     struct msghdr *msg, size_t size, int flags,
                     int *addr_len)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 ts       = bpf_ktime_get_ns();
    u64 sk_ptr   = (u64)(unsigned long)sk;

    /* Save sk pointer for the return probe */
    recv_sk_map.update(&pid_tgid, &sk_ptr);
    recv_start.update(&pid_tgid, &ts);

    /* Turnaround: time since last send on this socket */
    struct sock_key_t key = {};
    fill_sock_key(&key, sk);

    u64 *send_ts = last_send.lookup(&key);
    if (send_ts && *send_ts > 0) {
        u64 delta_us = (ts - *send_ts) / 1000;

        struct latency_event_t ev = {};
        bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
        ev.pid        = (u32)(pid_tgid >> 32);
        ev.tid        = (u32)(pid_tgid & 0xFFFFFFFF);
        ev.ts_ns      = ts;
        ev.delta_us   = delta_us;
        ev.saddr      = key.saddr;
        ev.daddr      = key.daddr;
        ev.sport      = key.sport;
        ev.dport      = key.dport;
        ev.event_type = 2;

        events.perf_submit(ctx, &ev, sizeof(ev));
        turnaround_lat_hist.increment(bpf_log2l(delta_us ? delta_us : 1));

        u64 zero = 0;
        last_send.update(&key, &zero);
    }
    return 0;
}

/* ── tcp_recvmsg: return — emit recv latency event ── */

int trace_recv_return(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 ts       = bpf_ktime_get_ns();

    u64 *start_ts = recv_start.lookup(&pid_tgid);
    u64 *sk_ptr   = recv_sk_map.lookup(&pid_tgid);
    if (!start_ts || !sk_ptr) return 0;

    u64 delta_us = (ts - *start_ts) / 1000;
    struct sock *sk = (struct sock *)(unsigned long)(*sk_ptr);
    struct sock_key_t key = {};
    fill_sock_key(&key, sk);

    struct latency_event_t ev = {};
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.pid        = (u32)(pid_tgid >> 32);
    ev.tid        = (u32)(pid_tgid & 0xFFFFFFFF);
    ev.ts_ns      = ts;
    ev.delta_us   = delta_us;
    ev.saddr      = key.saddr;
    ev.daddr      = key.daddr;
    ev.sport      = key.sport;
    ev.dport      = key.dport;
    ev.event_type = 1;

    events.perf_submit(ctx, &ev, sizeof(ev));
    recv_lat_hist.increment(bpf_log2l(delta_us ? delta_us : 1));

    recv_start.delete(&pid_tgid);
    recv_sk_map.delete(&pid_tgid);
    return 0;
}
"""

# ─── ctypes Event Structure ────────────────────────────────────────────────────

class LatencyEvent(ctypes.Structure):
    _fields_ = [
        ("pid",        ctypes.c_uint32),
        ("tid",        ctypes.c_uint32),
        ("ts_ns",      ctypes.c_uint64),
        ("delta_us",   ctypes.c_uint64),
        ("saddr",      ctypes.c_uint32),
        ("daddr",      ctypes.c_uint32),
        ("sport",      ctypes.c_uint16),
        ("dport",      ctypes.c_uint16),
        ("event_type", ctypes.c_uint8),
        ("comm",       ctypes.c_char * 16),
    ]

EVENT_SEND        = 0
EVENT_RECV        = 1
EVENT_TURNAROUND  = 2

EVENT_LABELS = {
    EVENT_SEND:       "SEND",
    EVENT_RECV:       "RECV",
    EVENT_TURNAROUND: "TURN",
}

EVENT_COLORS = {
    EVENT_SEND:       "cyan",
    EVENT_RECV:       "green",
    EVENT_TURNAROUND: "yellow",
}

# ─── Stats Accumulator ────────────────────────────────────────────────────────

class SocketStats:
    """Per-socket rolling statistics."""
    def __init__(self):
        self.count       = 0
        self.total_us    = 0
        self.min_us      = float("inf")
        self.max_us      = 0
        self.last_us     = 0
        self.last_ts     = 0
        self.comm        = b""
        self.pid         = 0

    def update(self, delta_us, ts_ns, comm, pid):
        self.count    += 1
        self.total_us += delta_us
        self.min_us    = min(self.min_us, delta_us)
        self.max_us    = max(self.max_us, delta_us)
        self.last_us   = delta_us
        self.last_ts   = ts_ns
        self.comm      = comm
        self.pid       = pid

    @property
    def avg_us(self):
        return self.total_us / self.count if self.count else 0


# ─── Helpers ──────────────────────────────────────────────────────────────────

def inet_ntoa(addr_int):
    """Convert packed 32-bit int (kernel byte order) to dotted-quad."""
    try:
        return socket.inet_ntoa(struct.pack("I", addr_int))
    except Exception:
        return "0.0.0.0"

def ntohs(port):
    return socket.ntohs(port)

def fmt_us(us):
    """Format microseconds into human-readable string."""
    if us < 1_000:
        return f"{us:.1f}µs"
    elif us < 1_000_000:
        return f"{us/1000:.2f}ms"
    else:
        return f"{us/1_000_000:.2f}s"

def latency_bar(us, max_us=100_000, width=12):
    """Render a small ASCII bar proportional to latency."""
    if max_us == 0:
        return " " * width
    ratio = min(us / max_us, 1.0)
    filled = int(ratio * width)
    bar = "█" * filled + "░" * (width - filled)
    return bar

HIST_UNITS = [
    (0,      "0µs"),
    (1,      "1µs"),
    (2,      "2µs"),
    (4,      "4µs"),
    (8,      "8µs"),
    (16,     "16µs"),
    (32,     "32µs"),
    (64,     "64µs"),
    (128,    "128µs"),
    (256,    "256µs"),
    (512,    "512µs"),
    (1024,   "1ms"),
    (2048,   "2ms"),
    (4096,   "4ms"),
    (8192,   "8ms"),
    (16384,  "16ms"),
    (32768,  "32ms"),
    (65536,  "65ms"),
    (131072, "131ms"),
    (262144, "262ms"),
    (524288, "524ms"),
    (1048576,"1s"),
]

# ─── Argument Parsing ─────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="eBPF Socket Turnaround Latency Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 socklatency.py                     # all sockets
  sudo python3 socklatency.py --pid 1234          # filter by PID
  sudo python3 socklatency.py --port 443          # filter by destination port
  sudo python3 socklatency.py --interval 2        # refresh every 2s
  sudo python3 socklatency.py --top 20            # show top 20 sockets
  sudo python3 socklatency.py --hist              # show latency histograms
  sudo python3 socklatency.py --json              # output JSON (no TUI)
        """,
    )
    p.add_argument("--pid",      type=int,   default=None,  help="Filter by PID")
    p.add_argument("--port",     type=int,   default=None,  help="Filter by remote port")
    p.add_argument("--interval", type=float, default=1.0,   help="Refresh interval in seconds (default: 1)")
    p.add_argument("--top",      type=int,   default=15,    help="Max rows in live table (default: 15)")
    p.add_argument("--hist",     action="store_true",        help="Print histograms on exit")
    p.add_argument("--json",     action="store_true",        help="JSON output mode (no TUI)")
    p.add_argument("--min-us",   type=int,   default=0,     help="Only show events >= this latency (µs)")
    return p.parse_args()

# ─── Global State ─────────────────────────────────────────────────────────────

args        = parse_args()
console     = Console()
lock        = threading.Lock()
events_buf  = collections.deque(maxlen=2000)

# keyed by (saddr, daddr, sport, dport, event_type)
socket_stats = collections.defaultdict(SocketStats)

total_events = {EVENT_SEND: 0, EVENT_RECV: 0, EVENT_TURNAROUND: 0}
start_time   = time.time()
running      = True

# ─── BPF Event Callback ───────────────────────────────────────────────────────

def handle_event(cpu, data, size):
    global running
    ev = ctypes.cast(data, ctypes.POINTER(LatencyEvent)).contents

    # PID filter
    if args.pid and ev.pid != args.pid:
        return

    # Port filter
    if args.port and ntohs(ev.dport) != args.port:
        return

    # Min latency filter
    if ev.delta_us < args.min_us:
        return

    key = (ev.saddr, ev.daddr, ev.sport, ev.dport, ev.event_type)

    with lock:
        socket_stats[key].update(ev.delta_us, ev.ts_ns, ev.comm, ev.pid)
        total_events[ev.event_type] = total_events.get(ev.event_type, 0) + 1
        events_buf.append({
            "pid":        ev.pid,
            "comm":       ev.comm.decode("utf-8", errors="replace").rstrip("\x00"),
            "saddr":      inet_ntoa(ev.saddr),
            "daddr":      inet_ntoa(ev.daddr),
            "sport":      ntohs(ev.sport),
            "dport":      ntohs(ev.dport),
            "type":       EVENT_LABELS.get(ev.event_type, "?"),
            "delta_us":   ev.delta_us,
            "ts_ns":      ev.ts_ns,
        })

    if args.json:
        import json
        rec = events_buf[-1]
        print(json.dumps(rec), flush=True)

# ─── TUI Rendering ────────────────────────────────────────────────────────────

def render_header():
    elapsed = time.time() - start_time
    ts      = datetime.now().strftime("%H:%M:%S")
    sends   = total_events.get(EVENT_SEND, 0)
    recvs   = total_events.get(EVENT_RECV, 0)
    turns   = total_events.get(EVENT_TURNAROUND, 0)
    total   = sends + recvs + turns

    title = Text()
    title.append("⚡ ", style="bold yellow")
    title.append("socklatency", style="bold white")
    title.append(" · eBPF Socket Turnaround Monitor", style="dim white")

    subtitle = Text()
    subtitle.append(f" {ts} ", style="bold green")
    subtitle.append(f"│ uptime {elapsed:.0f}s ", style="dim")
    subtitle.append(f"│ events: ", style="dim")
    subtitle.append(f"{sends} sends ", style="cyan")
    subtitle.append(f"{recvs} recvs ", style="green")
    subtitle.append(f"{turns} turnarounds ", style="yellow")
    subtitle.append(f"│ total {total}", style="bold white")

    if args.pid:
        subtitle.append(f" │ pid={args.pid}", style="bold magenta")
    if args.port:
        subtitle.append(f" │ port={args.port}", style="bold magenta")

    return Panel(
        Align.center(subtitle),
        title=title,
        border_style="bright_black",
        padding=(0, 1),
    )


def render_socket_table(stats_snapshot):
    """Top-N sockets by average latency."""
    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold bright_white",
        border_style="bright_black",
        row_styles=["", "dim"],
        expand=True,
    )

    table.add_column("PID",    style="magenta",      width=7,  no_wrap=True)
    table.add_column("COMM",   style="bold cyan",    width=14, no_wrap=True)
    table.add_column("TYPE",   style="bold",         width=6,  no_wrap=True)
    table.add_column("SRC",    style="bright_black", width=22, no_wrap=True)
    table.add_column("DST",    style="white",        width=22, no_wrap=True)
    table.add_column("COUNT",  style="dim white",    width=7,  justify="right")
    table.add_column("AVG",    style="bold",         width=10, justify="right")
    table.add_column("MIN",    style="green",        width=10, justify="right")
    table.add_column("MAX",    style="red",          width=10, justify="right")
    table.add_column("LAST",   style="yellow",       width=10, justify="right")
    table.add_column("DIST",   style="bright_black", width=14, no_wrap=True)

    # Sort by avg latency descending
    sorted_keys = sorted(
        stats_snapshot.keys(),
        key=lambda k: stats_snapshot[k].avg_us,
        reverse=True,
    )[:args.top]

    max_avg = max((stats_snapshot[k].avg_us for k in sorted_keys), default=1)

    for key in sorted_keys:
        saddr, daddr, sport, dport, etype = key
        st = stats_snapshot[key]

        src_str  = f"{inet_ntoa(saddr)}:{ntohs(sport)}"
        dst_str  = f"{inet_ntoa(daddr)}:{ntohs(dport)}"
        comm_str = st.comm.decode("utf-8", errors="replace").rstrip("\x00") if isinstance(st.comm, bytes) else str(st.comm)
        etype_label = EVENT_LABELS.get(etype, "?")
        etype_color = EVENT_COLORS.get(etype, "white")

        table.add_row(
            str(st.pid),
            comm_str,
            Text(etype_label, style=f"bold {etype_color}"),
            src_str,
            dst_str,
            str(st.count),
            fmt_us(st.avg_us),
            fmt_us(st.min_us) if st.min_us != float("inf") else "-",
            fmt_us(st.max_us),
            fmt_us(st.last_us),
            latency_bar(st.avg_us, max_avg),
        )

    if not sorted_keys:
        table.add_row("—", "—", "—", "—", "—", "—", "—", "—", "—", "—", "—")

    return Panel(
        table,
        title="[bold]Top Sockets by Average Latency[/bold]",
        border_style="bright_black",
        subtitle=f"[dim]showing {len(sorted_keys)} of {len(stats_snapshot)} active sockets[/dim]",
    )


def render_recent_events():
    """Last N raw events."""
    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold bright_white",
        border_style="bright_black",
        expand=True,
    )

    table.add_column("TIME",    style="dim",         width=9,  no_wrap=True)
    table.add_column("PID",     style="magenta",     width=7,  no_wrap=True)
    table.add_column("COMM",    style="cyan",        width=14, no_wrap=True)
    table.add_column("TYPE",    style="bold",        width=6,  no_wrap=True)
    table.add_column("DST",     style="white",       width=22, no_wrap=True)
    table.add_column("LATENCY", style="bold yellow", width=12, justify="right", no_wrap=True)

    with lock:
        recent = list(events_buf)[-12:]

    for ev in reversed(recent):
        ts_s     = ev["ts_ns"] / 1e9
        etype    = ev["type"]
        color    = {"SEND": "cyan", "RECV": "green", "TURN": "yellow"}.get(etype, "white")
        dst_str  = f"{ev['daddr']}:{ev['dport']}"

        table.add_row(
            f"{ts_s % 86400:.3f}",
            str(ev["pid"]),
            ev["comm"][:14],
            Text(etype, style=f"bold {color}"),
            dst_str,
            fmt_us(ev["delta_us"]),
        )

    return Panel(
        table,
        title="[bold]Recent Events[/bold]",
        border_style="bright_black",
    )


def make_display(stats_snapshot):
    from rich.layout import Layout

    layout = Layout()
    layout.split_column(
        Layout(render_header(),          name="header",  size=3),
        Layout(render_socket_table(stats_snapshot), name="table",   ratio=3),
        Layout(render_recent_events(),   name="recent",  ratio=2),
    )
    return layout


# ─── Histogram Printer ────────────────────────────────────────────────────────

def print_histograms(b):
    console.print("\n[bold yellow]─── Latency Histograms (log2 µs buckets) ─────────────────[/bold yellow]\n")

    for name, hist_map in [
        ("Send Latency",        b["send_lat_hist"]),
        ("Recv Latency",        b["recv_lat_hist"]),
        ("Turnaround Latency",  b["turnaround_lat_hist"]),
    ]:
        console.print(f"[bold cyan]{name}[/bold cyan]")
        hist_map.print_log2_hist("µs")
        console.print()


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    global running

    if os.geteuid() != 0:
        console.print("[bold red]ERROR:[/bold red] Must run as root (sudo)")
        sys.exit(1)

    console.print("[bold yellow]Loading eBPF program...[/bold yellow]", end=" ")

    try:
        b = BPF(text=BPF_PROGRAM)
    except Exception as e:
        console.print(f"\n[bold red]Failed to load BPF program:[/bold red] {e}")
        sys.exit(1)

    # Attach kprobes
    try:
        b.attach_kprobe(event="tcp_sendmsg",  fn_name="trace_send_entry")
        b.attach_kprobe(event="tcp_recvmsg",  fn_name="trace_recv_entry")
        b.attach_kretprobe(event="tcp_recvmsg", fn_name="trace_recv_return")
    except Exception as e:
        console.print(f"\n[bold red]Failed to attach kprobes:[/bold red] {e}")
        console.print("[dim]Kernel version may not support these probes.[/dim]")
        sys.exit(1)

    console.print("[bold green]OK[/bold green]")
    console.print(f"[dim]Attached kprobes on tcp_sendmsg / tcp_recvmsg. Press [bold]Ctrl+C[/bold] to stop.[/dim]\n")

    # Open perf buffer
    b["events"].open_perf_buffer(handle_event, page_cnt=512)

    def signal_handler(sig, frame):
        global running
        running = False

    signal.signal(signal.SIGINT,  signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if args.json:
        # JSON streaming mode — no TUI
        console.print("[dim]JSON streaming mode. Each line is a JSON event.[/dim]")
        while running:
            b.perf_buffer_poll(timeout=100)
        return

    # TUI mode
    poll_thread_stop = threading.Event()

    def poll_loop():
        while not poll_thread_stop.is_set():
            b.perf_buffer_poll(timeout=50)

    t = threading.Thread(target=poll_loop, daemon=True)
    t.start()

    try:
        with Live(
            console=console,
            refresh_per_second=int(1 / args.interval),
            screen=True,
        ) as live:
            while running:
                with lock:
                    stats_snapshot = {k: v for k, v in socket_stats.items()}
                live.update(make_display(stats_snapshot))
                time.sleep(args.interval)
    finally:
        poll_thread_stop.set()
        t.join(timeout=1)

    console.print("\n[bold yellow]Detaching probes...[/bold yellow]")

    if args.hist:
        print_histograms(b)

    # ── Per-socket final summary table ──────────────────────────────────────
    sends = total_events.get(EVENT_SEND, 0)
    recvs = total_events.get(EVENT_RECV, 0)
    turns = total_events.get(EVENT_TURNAROUND, 0)

    console.print()

    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold bright_white",
        border_style="bright_black",
        row_styles=["", "dim"],
        expand=True,
        title="[bold white]Session Summary — Per-Socket Statistics[/bold white]",
        title_style="bold",
        caption=(
            f"[cyan]{sends} sends[/cyan]  ·  "
            f"[green]{recvs} recvs[/green]  ·  "
            f"[yellow]{turns} turnarounds[/yellow]  ·  "
            f"[white]{len(socket_stats)} unique sockets[/white]"
        ),
    )

    table.add_column("PID",    style="magenta",      width=7,  no_wrap=True)
    table.add_column("COMM",   style="bold cyan",    width=14, no_wrap=True)
    table.add_column("TYPE",   style="bold",         width=6,  no_wrap=True)
    table.add_column("SRC",    style="bright_black", width=23, no_wrap=True)
    table.add_column("DST",    style="white",        width=23, no_wrap=True)
    table.add_column("COUNT",  style="dim white",    width=7,  justify="right")
    table.add_column("AVG",    style="bold yellow",  width=10, justify="right")
    table.add_column("MIN",    style="green",        width=10, justify="right")
    table.add_column("MAX",    style="red",          width=10, justify="right")
    table.add_column("LAST",   style="cyan",         width=10, justify="right")
    table.add_column("DIST",   style="bright_black", width=14, no_wrap=True)

    with lock:
        snapshot = dict(socket_stats)

    sorted_keys = sorted(
        snapshot.keys(),
        key=lambda k: snapshot[k].avg_us,
        reverse=True,
    )

    max_avg = max((snapshot[k].avg_us for k in sorted_keys), default=1)

    for key in sorted_keys:
        saddr, daddr, sport, dport, etype = key
        st = snapshot[key]

        src_str    = f"{inet_ntoa(saddr)}:{ntohs(sport)}"
        dst_str    = f"{inet_ntoa(daddr)}:{ntohs(dport)}"
        comm_str   = st.comm.decode("utf-8", errors="replace").rstrip("\x00") if isinstance(st.comm, bytes) else str(st.comm)
        etype_label = EVENT_LABELS.get(etype, "?")
        etype_color = EVENT_COLORS.get(etype, "white")
        min_str    = fmt_us(st.min_us) if st.min_us != float("inf") else "-"

        table.add_row(
            str(st.pid),
            comm_str,
            Text(etype_label, style=f"bold {etype_color}"),
            src_str,
            dst_str,
            str(st.count),
            fmt_us(st.avg_us),
            min_str,
            fmt_us(st.max_us),
            fmt_us(st.last_us),
            latency_bar(st.avg_us, max_avg),
        )

    if not sorted_keys:
        table.add_row("—", "—", "—", "—", "—", "—", "—", "—", "—", "—", "—")

    console.print(table)
    console.print(f"\n[dim]Done.[/dim]")


if __name__ == "__main__":
    main()
