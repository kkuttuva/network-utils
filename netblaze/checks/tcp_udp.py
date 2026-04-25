"""
TCP/UDP layer checks: buffers, retransmits, SYN flood, unclosed sockets, congestion.
"""
import re
from checks import CheckResult, OK, WARN, ERROR, SKIP, INFO
from runner import run, read_file

CATEGORY = "TCP/UDP"

# Thresholds
SYN_RECV_WARN = 100
CLOSE_WAIT_WARN = 500
TIME_WAIT_WARN = 2000
RETRANSMIT_RATE_WARN = 0.02    # 2% retransmit rate
SEND_QUEUE_WARN = 131072       # 128KB backed-up send queue


def _sysctl(key):
    out, _, rc = run(f"sysctl -n {key}")
    return out.strip() if rc == 0 and out else None


def check_connection_states():
    results = []
    stdout, _, rc = run("ss -s")
    if rc != 0 or not stdout:
        results.append(CheckResult(CATEGORY, "Connection states", SKIP, "ss -s failed"))
        return results

    state_map = {}
    for line in stdout.splitlines():
        for state in ["LISTEN", "ESTAB", "SYN-SENT", "SYN-RECV", "CLOSE-WAIT",
                      "TIME-WAIT", "FIN-WAIT", "LAST-ACK"]:
            m = re.search(rf"{state}\s+(\d+)", line, re.IGNORECASE)
            if m:
                state_map[state] = int(m.group(1))

    syn_recv = state_map.get("SYN-RECV", 0)
    close_wait = state_map.get("CLOSE-WAIT", 0)
    time_wait = state_map.get("TIME-WAIT", 0)
    estab = state_map.get("ESTAB", 0)

    if syn_recv > SYN_RECV_WARN:
        results.append(CheckResult(CATEGORY, "SYN-RECV count", ERROR,
                                   f"{syn_recv} SYN-RECV sockets (possible SYN flood)",
                                   "Enable SYN cookies: sysctl -w net.ipv4.tcp_syncookies=1; "
                                   "reduce net.ipv4.tcp_max_syn_backlog if needed"))
    else:
        results.append(CheckResult(CATEGORY, "SYN-RECV count", OK,
                                   f"SYN-RECV={syn_recv} (normal)"))

    if close_wait > CLOSE_WAIT_WARN:
        results.append(CheckResult(CATEGORY, "CLOSE-WAIT count", WARN,
                                   f"{close_wait} CLOSE-WAIT sockets (application not closing connections)",
                                   "Application is not calling close() on sockets; "
                                   "check app code or increase FD limits"))
    else:
        results.append(CheckResult(CATEGORY, "CLOSE-WAIT count", OK,
                                   f"CLOSE-WAIT={close_wait}"))

    if time_wait > TIME_WAIT_WARN:
        results.append(CheckResult(CATEGORY, "TIME-WAIT count", WARN,
                                   f"{time_wait} TIME-WAIT sockets",
                                   "Enable TIME-WAIT reuse: sysctl -w net.ipv4.tcp_tw_reuse=1; "
                                   "check net.ipv4.tcp_fin_timeout"))
    else:
        results.append(CheckResult(CATEGORY, "TIME-WAIT count", OK,
                                   f"TIME-WAIT={time_wait}"))

    results.append(CheckResult(CATEGORY, "Established connections", INFO,
                               f"ESTABLISHED={estab}"))
    return results


def check_tcp_buffers():
    results = []
    params = {
        "net.ipv4.tcp_rmem": (4096, 87380, 16777216),     # min, default, max recommended
        "net.ipv4.tcp_wmem": (4096, 16384, 16777216),
        "net.core.rmem_max": (None, None, 16777216),
        "net.core.wmem_max": (None, None, 16777216),
        "net.core.rmem_default": (None, None, 262144),
        "net.core.wmem_default": (None, None, 262144),
    }

    for param, (pmin, pdefault, recommended_max) in params.items():
        val_str = _sysctl(param)
        if val_str is None:
            results.append(CheckResult(CATEGORY, f"Buffer ({param})", SKIP,
                                       f"Could not read {param}"))
            continue

        parts = val_str.split()
        if len(parts) == 3:
            try:
                cur_max = int(parts[2])
            except ValueError:
                continue
            if cur_max < recommended_max // 4:
                results.append(CheckResult(CATEGORY, f"Buffer ({param})", WARN,
                                           f"{param} = {val_str} (max={cur_max} is small)",
                                           f"Consider: sysctl -w {param}=\"{pmin or 4096} "
                                           f"{pdefault or 131072} {recommended_max}\""))
            else:
                results.append(CheckResult(CATEGORY, f"Buffer ({param})", OK,
                                           f"{param} = {val_str}"))
        else:
            try:
                cur = int(parts[0])
            except ValueError:
                continue
            if cur < recommended_max // 4:
                results.append(CheckResult(CATEGORY, f"Buffer ({param})", WARN,
                                           f"{param} = {cur} (small)",
                                           f"Consider: sysctl -w {param}={recommended_max}"))
            else:
                results.append(CheckResult(CATEGORY, f"Buffer ({param})", OK,
                                           f"{param} = {cur}"))

    return results


def check_syn_flood_config():
    results = []
    syncookies = _sysctl("net.ipv4.tcp_syncookies")
    if syncookies == "0":
        results.append(CheckResult(CATEGORY, "SYN cookies", WARN,
                                   "SYN cookies disabled (net.ipv4.tcp_syncookies=0)",
                                   "Enable: sysctl -w net.ipv4.tcp_syncookies=1"))
    elif syncookies == "1":
        results.append(CheckResult(CATEGORY, "SYN cookies", OK, "SYN cookies enabled"))

    backlog = _sysctl("net.ipv4.tcp_max_syn_backlog")
    if backlog:
        bl = int(backlog)
        if bl < 1024:
            results.append(CheckResult(CATEGORY, "SYN backlog", WARN,
                                       f"tcp_max_syn_backlog={bl} (low)",
                                       "Consider: sysctl -w net.ipv4.tcp_max_syn_backlog=2048"))
        else:
            results.append(CheckResult(CATEGORY, "SYN backlog", OK,
                                       f"tcp_max_syn_backlog={bl}"))

    return results


def check_retransmits():
    results = []
    stdout, _, rc = run("netstat -s")
    if rc != 0 or not stdout:
        # Try ss fallback
        stdout, _, rc = run("ss -ti")
        if rc != 0 or not stdout:
            results.append(CheckResult(CATEGORY, "Retransmits", SKIP, "netstat -s and ss -ti failed"))
            return results

    # Parse netstat -s
    segments_sent = None
    retransmits = None
    fast_retrans = None
    checksum_errors = None

    for line in stdout.splitlines():
        m = re.search(r"(\d+) segments sent out", line)
        if m:
            segments_sent = int(m.group(1))
        m = re.search(r"(\d+) segments retransmitted", line)
        if m:
            retransmits = int(m.group(1))
        m = re.search(r"(\d+) fast retransmits", line)
        if m:
            fast_retrans = int(m.group(1))
        m = re.search(r"(\d+).*checksum error", line, re.IGNORECASE)
        if m:
            checksum_errors = int(m.group(1))

    if segments_sent and retransmits is not None:
        if segments_sent > 0:
            rate = retransmits / segments_sent
            if rate > RETRANSMIT_RATE_WARN:
                results.append(CheckResult(CATEGORY, "TCP retransmit rate", WARN,
                                           f"{retransmits}/{segments_sent} segments retransmitted "
                                           f"({rate*100:.1f}%)",
                                           "High retransmit rate indicates congestion or packet loss; "
                                           "check for duplex mismatch, buffer saturation, or path issues"))
            else:
                results.append(CheckResult(CATEGORY, "TCP retransmit rate", OK,
                                           f"Retransmit rate {rate*100:.2f}% "
                                           f"({retransmits}/{segments_sent})"))
    elif retransmits is not None:
        if retransmits > 1000:
            results.append(CheckResult(CATEGORY, "TCP retransmits", WARN,
                                       f"Total retransmits: {retransmits}",
                                       "Investigate congestion, packet loss, or network quality"))
        else:
            results.append(CheckResult(CATEGORY, "TCP retransmits", OK,
                                       f"Retransmits: {retransmits}"))

    if fast_retrans is not None and fast_retrans > 100:
        results.append(CheckResult(CATEGORY, "Fast retransmits", WARN,
                                   f"Fast retransmits: {fast_retrans}",
                                   "Packet loss causing fast retransmit; check link quality"))

    if checksum_errors is not None and checksum_errors > 0:
        results.append(CheckResult(CATEGORY, "TCP checksum errors", ERROR,
                                   f"TCP checksum errors: {checksum_errors}",
                                   "Hardware offload issue or NIC fault; "
                                   "try: ethtool -K <iface> tx-checksumming off rx-checksumming off"))

    return results


def check_socket_queues():
    results = []
    stdout, _, rc = run("ss -nt")
    if rc != 0 or not stdout:
        return results

    large_send_q = []
    large_recv_q = []

    for line in stdout.splitlines():
        if line.startswith("State") or line.startswith("Netid"):
            continue
        parts = line.split()
        if len(parts) >= 3:
            try:
                send_q = int(parts[1])
                recv_q = int(parts[2])
                if send_q > SEND_QUEUE_WARN:
                    large_send_q.append(f"{parts[-1]} SendQ={send_q}")
                if recv_q > SEND_QUEUE_WARN:
                    large_recv_q.append(f"{parts[-1]} RecvQ={recv_q}")
            except (ValueError, IndexError):
                pass

    if large_send_q:
        results.append(CheckResult(CATEGORY, "Socket Send-Q backlog", WARN,
                                   f"{len(large_send_q)} socket(s) with large Send-Q: "
                                   f"{'; '.join(large_send_q[:3])}",
                                   "Receiver not consuming data fast enough; "
                                   "check remote TCP window or network bandwidth"))
    else:
        results.append(CheckResult(CATEGORY, "Socket Send-Q", OK, "No large Send-Q backlogs"))

    if large_recv_q:
        results.append(CheckResult(CATEGORY, "Socket Recv-Q backlog", WARN,
                                   f"{len(large_recv_q)} socket(s) with large Recv-Q: "
                                   f"{'; '.join(large_recv_q[:3])}",
                                   "Application not reading from socket fast enough"))
    else:
        results.append(CheckResult(CATEGORY, "Socket Recv-Q", OK, "No large Recv-Q backlogs"))

    return results


def check_udp_buffers():
    results = []
    stdout, _, rc = run("netstat -su")
    if rc != 0 or not stdout:
        return results

    for line in stdout.splitlines():
        m = re.search(r"(\d+) packet receive errors", line)
        if m and int(m.group(1)) > 0:
            results.append(CheckResult(CATEGORY, "UDP receive errors", WARN,
                                       f"UDP packet receive errors: {m.group(1)}",
                                       "Increase UDP buffer: sysctl -w net.core.rmem_max=26214400"))
        m = re.search(r"(\d+) receive buffer errors", line)
        if m and int(m.group(1)) > 0:
            results.append(CheckResult(CATEGORY, "UDP buffer overflow", ERROR,
                                       f"UDP receive buffer errors: {m.group(1)}",
                                       "Buffer overflow; increase net.core.rmem_max and net.core.rmem_default"))
        m = re.search(r"(\d+) send buffer errors", line)
        if m and int(m.group(1)) > 0:
            results.append(CheckResult(CATEGORY, "UDP send buffer errors", WARN,
                                       f"UDP send buffer errors: {m.group(1)}",
                                       "Increase net.core.wmem_max"))

    return results


def check_congestion_control():
    results = []
    cc = _sysctl("net.ipv4.tcp_congestion_control")
    if cc:
        results.append(CheckResult(CATEGORY, "TCP congestion control", INFO,
                                   f"Algorithm: {cc}",
                                   "Consider 'bbr' for modern high-bandwidth links if using older algorithm"))

    fin_timeout = _sysctl("net.ipv4.tcp_fin_timeout")
    if fin_timeout:
        val = int(fin_timeout)
        if val > 60:
            results.append(CheckResult(CATEGORY, "TCP FIN timeout", WARN,
                                       f"tcp_fin_timeout={val}s (high)",
                                       "Reduce to 15-30s to free sockets faster: "
                                       "sysctl -w net.ipv4.tcp_fin_timeout=30"))
        else:
            results.append(CheckResult(CATEGORY, "TCP FIN timeout", OK,
                                       f"tcp_fin_timeout={val}s"))

    return results


def run_all():
    results = []
    results += check_connection_states()
    results += check_tcp_buffers()
    results += check_syn_flood_config()
    results += check_retransmits()
    results += check_socket_queues()
    results += check_udp_buffers()
    results += check_congestion_control()
    return results
