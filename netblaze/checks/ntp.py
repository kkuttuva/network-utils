"""
NTP checks: service running, time sync status, drift, server reachability.
"""
import re
from checks import CheckResult, OK, WARN, ERROR, SKIP, INFO
from runner import run, command_exists

CATEGORY = "NTP"

OFFSET_WARN_MS = 500     # ms
OFFSET_ERROR_MS = 5000   # ms
DRIFT_WARN = 100         # ppm


def _check_service(names):
    """Check if any of the given service names is active. Returns (name, active_bool) or (None, False)."""
    for name in names:
        out, _, rc = run(f"systemctl is-active {name}")
        if rc == 0 and out and out.strip() == "active":
            return name, True
        if out and out.strip() in ("inactive", "failed", "dead"):
            return name, False
    return None, False


def check_ntp_service():
    results = []
    service_names = ["chronyd", "ntpd", "ntp", "systemd-timesyncd"]
    active_name = None

    for name in service_names:
        out, _, rc = run(f"systemctl is-active {name}")
        if out:
            status = out.strip()
            if status == "active":
                active_name = name
                results.append(CheckResult(CATEGORY, "NTP service", OK,
                                           f"{name} is active"))
                break
            elif status in ("inactive", "failed"):
                results.append(CheckResult(CATEGORY, f"NTP service ({name})", WARN,
                                           f"{name} is {status}",
                                           f"Start with: systemctl start {name}"))

    if not active_name:
        results.append(CheckResult(CATEGORY, "NTP service", ERROR,
                                   "No NTP/time-sync service is active "
                                   "(checked: chronyd, ntpd, systemd-timesyncd)",
                                   "Install and enable chrony: "
                                   "apt install chrony && systemctl enable --now chronyd"))

    return results, active_name


def check_chrony(active_name):
    results = []
    if active_name != "chronyd":
        return results

    stdout, _, rc = run("chronyc tracking")
    if rc != 0 or not stdout:
        results.append(CheckResult(CATEGORY, "Chrony tracking", SKIP, "chronyc tracking failed"))
        return results

    # Reference
    ref_m = re.search(r"Reference ID\s+:\s+(.+)", stdout)
    if ref_m:
        ref = ref_m.group(1).strip()
        if ref.startswith("00000000") or "unsynchronised" in ref.lower():
            results.append(CheckResult(CATEGORY, "Chrony sync", ERROR,
                                       "chrony is NOT synchronised",
                                       "Check chrony sources: chronyc sources -v; "
                                       "verify NTP servers are reachable on UDP 123"))
        else:
            results.append(CheckResult(CATEGORY, "Chrony sync", OK, f"Synced to: {ref}"))

    # Offset
    offset_m = re.search(r"System time\s+:\s+([\d.]+)\s+seconds\s+(fast|slow)", stdout)
    if offset_m:
        offset_sec = float(offset_m.group(1))
        direction = offset_m.group(2)
        offset_ms = offset_sec * 1000
        if offset_ms > OFFSET_ERROR_MS:
            results.append(CheckResult(CATEGORY, "Time offset", ERROR,
                                       f"Offset {offset_ms:.1f}ms {direction} of NTP",
                                       "Large offset may break Kerberos/TLS; "
                                       "force sync: chronyc makestep"))
        elif offset_ms > OFFSET_WARN_MS:
            results.append(CheckResult(CATEGORY, "Time offset", WARN,
                                       f"Offset {offset_ms:.1f}ms {direction} of NTP",
                                       "Run 'chronyc makestep' to correct"))
        else:
            results.append(CheckResult(CATEGORY, "Time offset", OK,
                                       f"Offset {offset_ms:.1f}ms {direction}"))

    # Frequency (drift)
    freq_m = re.search(r"Frequency\s+:\s+([\d.]+)\s+ppm", stdout)
    if freq_m:
        drift = float(freq_m.group(1))
        if drift > DRIFT_WARN:
            results.append(CheckResult(CATEGORY, "Clock drift", WARN,
                                       f"Frequency drift {drift:.1f} ppm (high)",
                                       "High drift indicates HW clock issues or recent large time step"))
        else:
            results.append(CheckResult(CATEGORY, "Clock drift", OK, f"Drift {drift:.1f} ppm"))

    # Stratum
    stratum_m = re.search(r"Stratum\s+:\s+(\d+)", stdout)
    if stratum_m:
        stratum = int(stratum_m.group(1))
        if stratum == 0:
            results.append(CheckResult(CATEGORY, "NTP stratum", ERROR,
                                       "Stratum 0 — not synchronized",
                                       "Check NTP server connectivity"))
        elif stratum > 4:
            results.append(CheckResult(CATEGORY, "NTP stratum", WARN,
                                       f"Stratum {stratum} (far from root)",
                                       "Consider using closer NTP servers"))
        else:
            results.append(CheckResult(CATEGORY, "NTP stratum", OK, f"Stratum {stratum}"))

    # Sources reachability
    stdout2, _, rc2 = run("chronyc sources -v")
    if rc2 == 0 and stdout2:
        unreachable = re.findall(r"^\?.*", stdout2, re.MULTILINE)
        reachable = re.findall(r"^[*+].*", stdout2, re.MULTILINE)
        if not reachable:
            results.append(CheckResult(CATEGORY, "NTP sources", ERROR,
                                       "No reachable NTP sources",
                                       "Check firewall rules for UDP 123 outbound; "
                                       "verify /etc/chrony.conf server entries"))
        else:
            results.append(CheckResult(CATEGORY, "NTP sources", OK,
                                       f"{len(reachable)} reachable source(s)"))
        if unreachable:
            results.append(CheckResult(CATEGORY, "NTP unreachable sources", WARN,
                                       f"{len(unreachable)} source(s) unreachable: "
                                       f"{unreachable[0].strip()[:60]}",
                                       "Check DNS resolution and UDP 123 connectivity to NTP servers"))

    return results


def check_ntpd(active_name):
    results = []
    if active_name != "ntpd" and active_name != "ntp":
        return results

    if not command_exists("ntpq"):
        return results

    stdout, _, rc = run("ntpq -p")
    if rc != 0 or not stdout:
        results.append(CheckResult(CATEGORY, "ntpq -p", SKIP, "ntpq -p failed"))
        return results

    synced = re.search(r"^\*", stdout, re.MULTILINE)
    if not synced:
        results.append(CheckResult(CATEGORY, "NTP sync (ntpd)", ERROR,
                                   "No server selected (no '*' in ntpq -p)",
                                   "Check ntpd config and server reachability"))
    else:
        results.append(CheckResult(CATEGORY, "NTP sync (ntpd)", OK, "ntpd synchronized"))

    # Check offset from ntpq
    for line in stdout.splitlines():
        if line.startswith("*"):
            parts = line.split()
            if len(parts) >= 9:
                try:
                    offset_ms = float(parts[8])
                    if abs(offset_ms) > OFFSET_ERROR_MS:
                        results.append(CheckResult(CATEGORY, "Time offset (ntpd)", ERROR,
                                                   f"Offset {offset_ms:.1f}ms",
                                                   "Run 'ntpdate -u <server>' to force sync"))
                    elif abs(offset_ms) > OFFSET_WARN_MS:
                        results.append(CheckResult(CATEGORY, "Time offset (ntpd)", WARN,
                                                   f"Offset {offset_ms:.1f}ms"))
                    else:
                        results.append(CheckResult(CATEGORY, "Time offset (ntpd)", OK,
                                                   f"Offset {offset_ms:.1f}ms"))
                except ValueError:
                    pass

    return results


def check_timedatectl():
    results = []
    stdout, _, rc = run("timedatectl")
    if rc != 0 or not stdout:
        return results

    if "NTP synchronized: yes" in stdout or "System clock synchronized: yes" in stdout:
        results.append(CheckResult(CATEGORY, "timedatectl sync", OK, "System clock synchronized"))
    elif "NTP synchronized: no" in stdout or "System clock synchronized: no" in stdout:
        results.append(CheckResult(CATEGORY, "timedatectl sync", WARN,
                                   "System clock not synchronized via NTP",
                                   "Enable: timedatectl set-ntp true"))

    if "NTP service: active" in stdout or "systemd-timesyncd.service active" in stdout:
        pass  # covered by service check
    elif "NTP service: inactive" in stdout:
        results.append(CheckResult(CATEGORY, "NTP service (timedatectl)", WARN,
                                   "NTP service inactive per timedatectl",
                                   "Enable: timedatectl set-ntp true"))

    return results


def run_all():
    results = []
    service_results, active_name = check_ntp_service()
    results += service_results
    results += check_chrony(active_name)
    results += check_ntpd(active_name)
    results += check_timedatectl()
    return results
