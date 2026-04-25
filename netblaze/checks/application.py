"""
Application layer checks: SSL errors, memory pressure, OOM events, open FDs, listening services.
"""
import re
from checks import CheckResult, OK, WARN, ERROR, SKIP, INFO
from runner import run, read_file, command_exists

CATEGORY = "Application"

MEM_WARN_PCT = 10      # warn if available < 10% of total
SWAP_WARN_PCT = 50     # warn if swap usage > 50%
FD_WARN_PCT = 80       # warn if FD usage > 80%


def check_ssl_errors():
    results = []
    found = False

    # Check journalctl
    if command_exists("journalctl"):
        stdout, _, rc = run(
            "journalctl -n 200 --no-pager -q", sudo=True, timeout=15
        )
        if rc == 0 and stdout:
            ssl_patterns = [
                r"SSL[_ ]handshake.*fail",
                r"certificate verify failed",
                r"ssl_error",
                r"TLS.*alert",
                r"handshake failure",
                r"CERTIFICATE_VERIFY_FAILED",
            ]
            for pattern in ssl_patterns:
                matches = re.findall(pattern, stdout, re.IGNORECASE)
                if matches:
                    found = True
                    results.append(CheckResult(CATEGORY, "SSL/TLS errors", WARN,
                                               f"SSL/TLS error in journal: '{matches[0][:80]}'",
                                               "Check certificate validity, CA chain, and clock sync (NTP)"))
        elif rc == -2:
            results.append(CheckResult(CATEGORY, "SSL/TLS errors (journal)", SKIP,
                                       "Requires sudo to read journal"))

    # Check syslog fallback
    for logfile in ["/var/log/syslog", "/var/log/messages"]:
        content = read_file(logfile)
        if content:
            for pattern in [r"SSL.*error", r"certificate.*expired", r"handshake.*fail"]:
                matches = re.findall(pattern, content[-50000:], re.IGNORECASE)
                if matches:
                    found = True
                    results.append(CheckResult(CATEGORY, "SSL/TLS errors (syslog)", WARN,
                                               f"SSL error in {logfile}: '{matches[0][:80]}'",
                                               "Check application TLS config and certificate expiry"))

    if not found:
        results.append(CheckResult(CATEGORY, "SSL/TLS errors", OK, "No SSL/TLS errors found in recent logs"))
    return results


def check_memory():
    results = []
    content = read_file("/proc/meminfo")
    if not content:
        results.append(CheckResult(CATEGORY, "Memory", SKIP, "/proc/meminfo not readable"))
        return results

    mem = {}
    for line in content.splitlines():
        m = re.match(r"(\w+):\s+(\d+)", line)
        if m:
            mem[m.group(1)] = int(m.group(2))  # kB

    total = mem.get("MemTotal", 0)
    available = mem.get("MemAvailable", 0)
    swap_total = mem.get("SwapTotal", 0)
    swap_free = mem.get("SwapFree", 0)

    if total > 0:
        avail_pct = (available / total) * 100
        if avail_pct < MEM_WARN_PCT:
            results.append(CheckResult(CATEGORY, "Memory available", ERROR,
                                       f"Only {avail_pct:.1f}% memory available "
                                       f"({available//1024}MB free of {total//1024}MB)",
                                       "System under memory pressure; identify top consumers with 'ps aux --sort=-%mem'"))
        elif avail_pct < 20:
            results.append(CheckResult(CATEGORY, "Memory available", WARN,
                                       f"{avail_pct:.1f}% memory available ({available//1024}MB)"))
        else:
            results.append(CheckResult(CATEGORY, "Memory available", OK,
                                       f"{avail_pct:.1f}% available ({available//1024}MB of {total//1024}MB)"))

    if swap_total > 0:
        swap_used = swap_total - swap_free
        swap_pct = (swap_used / swap_total) * 100
        if swap_pct > SWAP_WARN_PCT:
            results.append(CheckResult(CATEGORY, "Swap usage", WARN,
                                       f"Swap {swap_pct:.1f}% used ({swap_used//1024}MB/{swap_total//1024}MB)",
                                       "High swap use degrades network performance; "
                                       "add RAM or reduce memory-hungry services"))
        else:
            results.append(CheckResult(CATEGORY, "Swap usage", OK,
                                       f"Swap {swap_pct:.1f}% used"))
    else:
        results.append(CheckResult(CATEGORY, "Swap", INFO, "No swap configured"))

    return results


def check_oom_events():
    results = []
    stdout, _, rc = run("dmesg")
    if rc != 0 or not stdout:
        return results

    oom_lines = [l for l in stdout.splitlines() if re.search(r"oom.kill|out of memory|oom_reaper", l, re.IGNORECASE)]
    if oom_lines:
        results.append(CheckResult(CATEGORY, "OOM events", ERROR,
                                   f"{len(oom_lines)} OOM killer event(s) in dmesg: "
                                   f"'{oom_lines[-1].strip()[:100]}'",
                                   "OOM kills may terminate network services; "
                                   "add RAM, tune vm.overcommit_memory, or set memory limits on processes"))
    else:
        results.append(CheckResult(CATEGORY, "OOM events", OK, "No OOM killer events in dmesg"))
    return results


def check_open_fds():
    results = []
    content = read_file("/proc/sys/fs/file-nr")
    if content:
        parts = content.split()
        if len(parts) >= 3:
            try:
                allocated = int(parts[0])
                maximum = int(parts[2])
                if maximum > 0:
                    pct = (allocated / maximum) * 100
                    if pct > FD_WARN_PCT:
                        results.append(CheckResult(CATEGORY, "File descriptors", ERROR,
                                                   f"{allocated}/{maximum} FDs in use ({pct:.1f}%)",
                                                   "Near FD limit; increase: sysctl -w fs.file-max=<higher_value>"))
                    elif pct > 60:
                        results.append(CheckResult(CATEGORY, "File descriptors", WARN,
                                                   f"{allocated}/{maximum} FDs in use ({pct:.1f}%)",
                                                   "Growing FD usage; monitor and consider increasing fs.file-max"))
                    else:
                        results.append(CheckResult(CATEGORY, "File descriptors", OK,
                                                   f"{allocated}/{maximum} FDs in use ({pct:.1f}%)"))
            except ValueError:
                pass
    return results


def check_listening_services():
    results = []
    stdout, _, rc = run("ss -tlnp")
    if rc != 0 or not stdout:
        stdout, _, rc = run("ss -tlnp", sudo=True)
        if rc != 0 or not stdout:
            results.append(CheckResult(CATEGORY, "Listening services", SKIP, "ss -tlnp failed"))
            return results

    lines = [l for l in stdout.splitlines() if "LISTEN" in l]
    if not lines:
        results.append(CheckResult(CATEGORY, "Listening services", WARN,
                                   "No TCP listening sockets found",
                                   "Verify expected services are running"))
    else:
        results.append(CheckResult(CATEGORY, "Listening services", INFO,
                                   f"{len(lines)} TCP service(s) listening"))

    # Flag services bound to 0.0.0.0 unexpectedly
    public_listeners = []
    for line in lines:
        if "0.0.0.0:" in line or ":::":
            m = re.search(r"0\.0\.0\.0:(\d+)|:::(\d+)", line)
            if m:
                port = m.group(1) or m.group(2)
                proc_m = re.search(r'users:\(\("([^"]+)"', line)
                proc = proc_m.group(1) if proc_m else "unknown"
                public_listeners.append(f"{proc}:{port}")

    if len(public_listeners) > 10:
        results.append(CheckResult(CATEGORY, "Public listeners", INFO,
                                   f"{len(public_listeners)} services listening on all interfaces",
                                   "Review if all services should be publicly accessible"))

    return results


def run_all():
    results = []
    results += check_ssl_errors()
    results += check_memory()
    results += check_oom_events()
    results += check_open_fds()
    results += check_listening_services()
    return results
