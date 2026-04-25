"""
Socket/netstat checks: drops, overflows, exhaustion via /proc/net/sockstat and netstat -s.
"""
import re
from checks import CheckResult, OK, WARN, ERROR, SKIP, INFO
from runner import run, read_file

CATEGORY = "Sockstat"

ORPHAN_WARN = 1000
TIMEWAIT_WARN = 10000
UNIX_WARN = 5000


def check_sockstat():
    results = []
    content = read_file("/proc/net/sockstat")
    if not content:
        results.append(CheckResult(CATEGORY, "/proc/net/sockstat", SKIP, "Not available"))
        return results

    for line in content.splitlines():
        if line.startswith("TCP:"):
            parts = dict(zip(line.split()[1::2], [int(x) for x in line.split()[2::2]]))
            inuse = parts.get("inuse", 0)
            orphan = parts.get("orphan", 0)
            tw = parts.get("tw", 0)
            alloc = parts.get("alloc", 0)
            mem = parts.get("mem", 0)

            results.append(CheckResult(CATEGORY, "TCP sockets in use", INFO,
                                       f"inuse={inuse}, alloc={alloc}, mem_pages={mem}"))

            if orphan > ORPHAN_WARN:
                results.append(CheckResult(CATEGORY, "TCP orphan sockets", WARN,
                                           f"{orphan} orphaned TCP sockets",
                                           "Orphaned sockets waste memory; "
                                           "reduce net.ipv4.tcp_max_orphans or fix app to close connections"))
            else:
                results.append(CheckResult(CATEGORY, "TCP orphan sockets", OK,
                                           f"Orphaned sockets: {orphan}"))

            if tw > TIMEWAIT_WARN:
                results.append(CheckResult(CATEGORY, "TCP TIME-WAIT", WARN,
                                           f"{tw} TIME-WAIT sockets",
                                           "sysctl -w net.ipv4.tcp_tw_reuse=1; "
                                           "reduce net.ipv4.tcp_fin_timeout"))
            else:
                results.append(CheckResult(CATEGORY, "TCP TIME-WAIT", OK, f"TIME-WAIT sockets: {tw}"))

        elif line.startswith("UDP:"):
            parts = dict(zip(line.split()[1::2], [int(x) for x in line.split()[2::2]]))
            mem = parts.get("mem", 0)
            if mem > 1000:
                results.append(CheckResult(CATEGORY, "UDP memory", WARN,
                                           f"UDP mem pages: {mem} (may indicate buffer pressure)",
                                           "Increase net.core.rmem_max and net.core.wmem_max"))
            else:
                results.append(CheckResult(CATEGORY, "UDP memory", OK, f"UDP mem pages: {mem}"))

        elif line.startswith("UNIX:"):
            m = re.search(r"inuse\s+(\d+)", line)
            if m:
                unix_count = int(m.group(1))
                if unix_count > UNIX_WARN:
                    results.append(CheckResult(CATEGORY, "UNIX sockets", WARN,
                                               f"{unix_count} UNIX sockets in use",
                                               "Unusually high UNIX socket count; "
                                               "check for socket leaks in local services"))
                else:
                    results.append(CheckResult(CATEGORY, "UNIX sockets", OK,
                                               f"UNIX sockets in use: {unix_count}"))

    return results


def check_netstat_drops():
    results = []
    stdout, _, rc = run("netstat -s")
    if rc != 0 or not stdout:
        results.append(CheckResult(CATEGORY, "netstat -s", SKIP, "netstat not available"))
        return results

    checks = [
        (r"(\d+) packets? received", None, "IP packets received", INFO),
        (r"(\d+) packet receive errors?", WARN, "IP packet receive errors",
         "Check NIC ring buffers, IRQ handling, and softirq budget"),
        (r"(\d+) reassembly failures?", WARN, "IP reassembly failures",
         "Fragmented packets being dropped; check MTU configuration"),
        (r"(\d+) outgoing packets? dropped", WARN, "Outgoing packet drops",
         "TX queue drops; check txqueuelen and NIC buffer"),
        (r"(\d+) fragments? dropped after timeout", WARN, "Fragment timeout drops",
         "Increase net.ipv4.ipfrag_time or fix MTU issues"),
        (r"(\d+) (bad|invalid) header", ERROR, "IP header errors",
         "IP header corruption; check NIC offloading or upstream equipment"),
        (r"(\d+) connection resets? received", INFO, "TCP resets received", ""),
        (r"(\d+) connections? aborted", WARN, "TCP connections aborted",
         "High abort count may indicate network instability or application issues"),
        (r"(\d+) times? the listen queue of a socket overflowed", ERROR, "Listen queue overflow",
         "Increase net.core.somaxconn and application listen() backlog"),
        (r"(\d+) SYNs? to LISTEN sockets? dropped", ERROR, "SYN to LISTEN dropped",
         "Accept backlog overflow; increase net.core.somaxconn"),
    ]

    for pattern, status, label, rec in checks:
        m = re.search(pattern, stdout, re.IGNORECASE)
        if m:
            count = int(m.group(1))
            if status is None:
                results.append(CheckResult(CATEGORY, label, INFO, f"{label}: {count}"))
            elif count == 0:
                results.append(CheckResult(CATEGORY, label, OK, f"{label}: 0"))
            else:
                results.append(CheckResult(CATEGORY, label, status, f"{label}: {count}", rec))

    return results


def check_ss_summary():
    results = []
    stdout, _, rc = run("ss -s")
    if rc != 0 or not stdout:
        return results

    total_m = re.search(r"Total:\s+(\d+)", stdout)
    tcp_m = re.search(r"TCP:\s+(\d+)\s+\(estab\s+(\d+)", stdout)

    if total_m:
        results.append(CheckResult(CATEGORY, "Total sockets", INFO,
                                   f"Total sockets: {total_m.group(1)}"))
    if tcp_m:
        results.append(CheckResult(CATEGORY, "TCP established", INFO,
                                   f"TCP total={tcp_m.group(1)}, established={tcp_m.group(2)}"))
    return results


def run_all():
    results = []
    results += check_sockstat()
    results += check_netstat_drops()
    results += check_ss_summary()
    return results
