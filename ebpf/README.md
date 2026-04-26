# socklatency — eBPF Socket Send/Receive Turnaround Monitor

Measure the **send → receive turnaround time** for every TCP socket on your
system using eBPF kprobes — with zero application changes and microsecond
precision.

```
⚡ socklatency · eBPF Socket Turnaround Monitor
 14:32:11 │ uptime 42s │ events: 318 sends  412 recvs  291 turnarounds │ total 1021

 PID     COMM           TYPE  SRC                    DST                    COUNT  AVG        MIN        MAX        LAST       DIST
 ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 2841    curl           TURN  10.0.2.15:51204        93.184.216.34:443      12     4.21ms     892µs      11.3ms     3.14ms     ████████░░░░
 1234    nginx          RECV  0.0.0.0:80             192.168.1.10:54312     89     142µs      18µs       2.1ms      98µs       ████░░░░░░░░
 891     sshd           TURN  10.0.2.15:22           10.0.2.2:58901         4      211µs      88µs       401µs      195µs      ██░░░░░░░░░░
```

---

## What it measures

| Event        | Description                                                          |
|--------------|----------------------------------------------------------------------|
| `SEND`       | `tcp_sendmsg` entry — marks the start of a send                     |
| `RECV`       | Duration of a `tcp_recvmsg` call                                     |
| `TURN`       | **Send → receive turnaround**: time from last `tcp_sendmsg` on a socket until the next `tcp_recvmsg` on the same socket. This is the request-response latency from the kernel's perspective. |

---

## Requirements

| Component         | Package                      | Install                                  |
|-------------------|------------------------------|------------------------------------------|
| Linux kernel      | ≥ 4.4                        | —                                        |
| BPF Compiler Collection | `python3-bpfcc` + `bpfcc-tools` | `sudo apt install python3-bpfcc bpfcc-tools` |
| Rich TUI          | `rich`                       | `pip3 install --break-system-packages rich` |
| Root access       | —                            | `sudo`                                   |

---

## Installation

```bash
# 1. Clone / copy the files
git clone <repo> socklatency && cd socklatency

# 2. Install system dependencies
sudo apt install python3-bpfcc bpfcc-tools

# 3. Install Python display library
pip3 install --break-system-packages rich

# 4. Make wrapper executable
chmod +x socklatency
```

---

## Usage

```bash
# Monitor all TCP sockets (full TUI dashboard)
sudo ./socklatency

# Filter by PID
sudo ./socklatency --pid 1234

# Filter by remote port (e.g. HTTPS)
sudo ./socklatency --port 443

# Faster refresh rate
sudo ./socklatency --interval 0.5

# Show more rows
sudo ./socklatency --top 30

# Only show events with latency >= 1ms
sudo ./socklatency --min-us 1000

# Show latency histograms on exit
sudo ./socklatency --hist

# JSON streaming (for piping / log ingestion)
sudo ./socklatency --json | jq .

# Combine filters
sudo ./socklatency --port 80 --min-us 500 --hist
```

---

## Architecture

```
┌───────────────────── Kernel Space (eBPF) ──────────────────────────┐
│                                                                      │
│  tcp_sendmsg ──kprobe──► trace_send_entry()                         │
│    • stores timestamp in last_send[sock_key]                        │
│                                                                      │
│  tcp_recvmsg ──kprobe──► trace_recv_entry()                         │
│    • looks up last_send[sock_key]                                    │
│    • emits TURNAROUND event (delta = now - last_send)               │
│    • starts recv timer                                               │
│                                                                      │
│  tcp_recvmsg ─kretprobe─► trace_recv_return()                       │
│    • emits RECV event (duration of recvmsg call)                    │
│                                                                      │
│  BPF Maps:  last_send, recv_start, recv_sk_map                     │
│  Output:    perf_buffer → userspace                                  │
│  Histograms: send_lat_hist, recv_lat_hist, turnaround_lat_hist      │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
                              │ perf_buffer
                              ▼
┌───────────────────── User Space (Python) ───────────────────────────┐
│                                                                      │
│  handle_event()  ──►  socket_stats{}  ──►  Rich TUI / JSON          │
│                                                                      │
│  Live dashboard: top-N sockets by avg latency + recent event log    │
│  Histograms on exit (--hist)                                         │
│  JSON streaming mode (--json)                                        │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Output Fields

| Field   | Meaning                                       |
|---------|-----------------------------------------------|
| PID     | Process ID that owns the socket               |
| COMM    | Process name (comm)                           |
| TYPE    | SEND / RECV / TURN (turnaround)               |
| SRC     | Source IP:port                                |
| DST     | Destination IP:port                           |
| COUNT   | Number of events captured                    |
| AVG     | Mean latency                                  |
| MIN     | Minimum latency observed                      |
| MAX     | Maximum / worst-case latency                  |
| LAST    | Most recent latency                           |
| DIST    | ASCII bar showing avg relative to max observed|

---

## JSON Mode

Each line is a self-contained JSON object:

```json
{
  "pid": 2841,
  "comm": "curl",
  "saddr": "10.0.2.15",
  "daddr": "93.184.216.34",
  "sport": 51204,
  "dport": 443,
  "type": "TURN",
  "delta_us": 4213,
  "ts_ns": 1234567890123456789
}
```

Pipe to `jq`, InfluxDB line protocol, or any log shipper.

---

## Limitations

- Measures **kernel-level** send→recv gap — includes network RTT plus kernel
  scheduling jitter. Application-level processing time is not visible.
- Only TCP sockets (hooks on `tcp_sendmsg` / `tcp_recvmsg`). For UDP, similar
  hooks on `udp_sendmsg` / `udp_recvmsg` can be added.
- Requires kernel ≥ 4.4 with `CONFIG_BPF_SYSCALL=y` and `CONFIG_KPROBES=y`.
- On kernels < 5.8, CO-RE (compile-once-run-everywhere) is unavailable; BCC's
  JIT compilation is used instead (requires kernel headers or BTF).
- The turnaround metric assumes a request-response pattern. For streaming
  sockets, it measures the gap between any outgoing write and the next read,
  which may not reflect application semantics.

---

## Extending

The tool is intentionally modular. Common extensions:

**Add UDP support:**
```python
b.attach_kprobe(event="udp_sendmsg", fn_name="trace_send_entry")
b.attach_kprobe(event="udp_recvmsg", fn_name="trace_recv_entry")
b.attach_kretprobe(event="udp_recvmsg", fn_name="trace_recv_return")
```

**Export to Prometheus:**
Replace `handle_event` with a Prometheus counter/histogram update and expose
`/metrics` via `prometheus_client`.

**Write to InfluxDB / Grafana:**
Serialize events from the `events_buf` deque to InfluxDB line protocol in a
background thread.
