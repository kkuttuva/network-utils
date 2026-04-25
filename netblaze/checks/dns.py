"""
DNS checks: resolution, /etc/resolv.conf, /etc/hosts anomalies, server reachability, PTR.
"""
import re
from checks import CheckResult, OK, WARN, ERROR, SKIP, INFO
from runner import run, read_file, command_exists

CATEGORY = "DNS"

TEST_DOMAIN = "www.google.com"
KNOWN_GOOD_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"}


def check_resolution():
    results = []
    tool = None
    if command_exists("dig"):
        tool = "dig"
    elif command_exists("nslookup"):
        tool = "nslookup"
    elif command_exists("host"):
        tool = "host"

    if not tool:
        results.append(CheckResult(CATEGORY, "DNS resolution", SKIP,
                                   "No DNS lookup tool available (dig/nslookup/host)",
                                   "Install dnsutils: apt install dnsutils"))
        return results

    if tool == "dig":
        stdout, _, rc = run(f"dig +short {TEST_DOMAIN}", timeout=10)
        if rc != 0 or not stdout or not stdout.strip():
            results.append(CheckResult(CATEGORY, "DNS resolution", ERROR,
                                       f"dig {TEST_DOMAIN} returned no result",
                                       "Check /etc/resolv.conf nameservers and network connectivity"))
        else:
            ips = [l.strip() for l in stdout.splitlines() if re.match(r"\d+\.\d+\.\d+\.\d+", l.strip())]
            if ips:
                results.append(CheckResult(CATEGORY, "DNS resolution", OK,
                                           f"{TEST_DOMAIN} resolves to: {', '.join(ips[:3])}"))
            else:
                results.append(CheckResult(CATEGORY, "DNS resolution", WARN,
                                           f"dig returned non-IP output: {stdout.strip()[:80]}"))
    elif tool == "nslookup":
        stdout, _, rc = run(f"nslookup {TEST_DOMAIN}", timeout=10)
        if rc != 0 or "NXDOMAIN" in (stdout or "") or "SERVFAIL" in (stdout or ""):
            results.append(CheckResult(CATEGORY, "DNS resolution", ERROR,
                                       f"nslookup {TEST_DOMAIN} failed",
                                       "Check DNS configuration"))
        else:
            results.append(CheckResult(CATEGORY, "DNS resolution", OK,
                                       f"{TEST_DOMAIN} resolves (nslookup)"))
    elif tool == "host":
        stdout, _, rc = run(f"host {TEST_DOMAIN}", timeout=10)
        if rc != 0:
            results.append(CheckResult(CATEGORY, "DNS resolution", ERROR,
                                       f"host {TEST_DOMAIN} failed: {(stdout or '').strip()[:80]}",
                                       "Check DNS configuration"))
        else:
            results.append(CheckResult(CATEGORY, "DNS resolution", OK,
                                       f"{TEST_DOMAIN} resolves (host)"))

    return results


def check_resolv_conf():
    results = []
    content = read_file("/etc/resolv.conf")
    if not content:
        results.append(CheckResult(CATEGORY, "/etc/resolv.conf", ERROR,
                                   "/etc/resolv.conf missing or unreadable",
                                   "Create /etc/resolv.conf with nameserver entries"))
        return results

    nameservers = re.findall(r"^nameserver\s+(\S+)", content, re.MULTILINE)
    search_domains = re.findall(r"^(?:search|domain)\s+(.+)", content, re.MULTILINE)

    if not nameservers:
        results.append(CheckResult(CATEGORY, "Nameservers", ERROR,
                                   "No nameserver entries in /etc/resolv.conf",
                                   "Add: nameserver 8.8.8.8"))
    else:
        loopback_only = all(ns.startswith("127.") for ns in nameservers)
        if loopback_only:
            results.append(CheckResult(CATEGORY, "Nameservers", INFO,
                                       f"Loopback-only nameservers: {nameservers} (local resolver)",
                                       "Ensure local resolver (systemd-resolved/dnsmasq) is running"))
        else:
            results.append(CheckResult(CATEGORY, "Nameservers", OK,
                                       f"Nameservers: {', '.join(nameservers)}"))

    # Check each nameserver is reachable
    for ns in nameservers:
        if ns.startswith("127.") or ns == "::1":
            continue
        if command_exists("dig"):
            out, _, rc = run(f"dig @{ns} {TEST_DOMAIN} +short +time=3 +tries=1", timeout=8)
            if rc != 0 or not (out or "").strip():
                results.append(CheckResult(CATEGORY, f"Nameserver ({ns})", WARN,
                                           f"Nameserver {ns} did not respond to test query",
                                           "Check firewall rules for UDP/TCP 53 to this server"))
            else:
                results.append(CheckResult(CATEGORY, f"Nameserver ({ns})", OK,
                                           f"Nameserver {ns} is responsive"))

    if len(nameservers) == 1:
        results.append(CheckResult(CATEGORY, "Nameserver redundancy", WARN,
                                   "Only one nameserver configured",
                                   "Add a secondary nameserver for redundancy"))

    return results


def check_hosts_file():
    results = []
    content = read_file("/etc/hosts")
    if not content:
        return results

    issues = []
    seen_names = {}

    for lineno, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip = parts[0]
        names = parts[1:]

        for name in names:
            # Flag public internet domains overridden in /etc/hosts
            if re.search(r"\.(com|net|org|io|gov|edu)$", name, re.IGNORECASE):
                # Allowed exceptions: localhost.localdomain etc
                if not name.startswith("localhost"):
                    issues.append(f"line {lineno}: public domain '{name}' mapped to {ip}")

            # Duplicate hostname entries
            if name in seen_names:
                issues.append(f"line {lineno}: duplicate hostname '{name}' (also line {seen_names[name]})")
            else:
                seen_names[name] = lineno

        # Check for obviously wrong IPs
        if ip not in ("127.0.0.1", "::1", "127.0.1.1", "0.0.0.0"):
            # Non-loopback entry — just note it
            pass

    if issues:
        for issue in issues[:5]:
            results.append(CheckResult(CATEGORY, "/etc/hosts anomaly", WARN,
                                       issue,
                                       "Review /etc/hosts for unintended overrides or DNS hijacking"))
    else:
        results.append(CheckResult(CATEGORY, "/etc/hosts", OK, "No anomalies in /etc/hosts"))

    return results


def check_nsswitch():
    results = []
    content = read_file("/etc/nsswitch.conf")
    if not content:
        return results

    for line in content.splitlines():
        if re.match(r"^\s*hosts:", line):
            if "dns" not in line:
                results.append(CheckResult(CATEGORY, "nsswitch.conf (hosts)", ERROR,
                                           f"'dns' missing from hosts line: {line.strip()}",
                                           "Add 'dns' to hosts: entry in /etc/nsswitch.conf"))
            elif "files" in line and "dns" in line:
                results.append(CheckResult(CATEGORY, "nsswitch.conf (hosts)", OK,
                                           f"Hosts lookup order: {line.strip()}"))
            break

    return results


def check_reverse_dns():
    results = []
    stdout, _, rc = run("ip addr show")
    if rc != 0 or not stdout:
        return results

    own_ips = re.findall(r"inet (\d+\.\d+\.\d+\.\d+)/", stdout)
    public_ips = [ip for ip in own_ips if not (
        ip.startswith("127.") or ip.startswith("10.") or
        ip.startswith("192.168.") or ip.startswith("169.254.") or
        re.match(r"172\.(1[6-9]|2[0-9]|3[01])\.", ip)
    )]

    if not public_ips:
        return results

    if not command_exists("dig"):
        return results

    for ip in public_ips[:2]:
        stdout2, _, rc2 = run(f"dig -x {ip} +short +time=3 +tries=1", timeout=8)
        if rc2 == 0 and stdout2 and stdout2.strip():
            results.append(CheckResult(CATEGORY, f"Reverse DNS ({ip})", OK,
                                       f"PTR: {stdout2.strip()[:60]}"))
        else:
            results.append(CheckResult(CATEGORY, f"Reverse DNS ({ip})", INFO,
                                       f"No PTR record for {ip}",
                                       "Missing PTR record may affect email deliverability"))

    return results


def run_all():
    results = []
    results += check_resolution()
    results += check_resolv_conf()
    results += check_hosts_file()
    results += check_nsswitch()
    results += check_reverse_dns()
    return results
