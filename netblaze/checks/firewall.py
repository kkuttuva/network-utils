"""
Firewall checks: iptables/nftables drop rules, conntrack table saturation.
"""
import re
from checks import CheckResult, OK, WARN, ERROR, SKIP, INFO
from runner import run, command_exists

CATEGORY = "Firewall"

DROP_COUNT_WARN = 1000        # iptables rule drop packet count to warn on
CONNTRACK_WARN_PCT = 80


def _parse_iptables(output):
    """Parse iptables -L -n -v output, return list of (chain, target, pkts, bytes, rule)."""
    rows = []
    current_chain = None
    for line in output.splitlines():
        chain_m = re.match(r"^Chain\s+(\S+)\s+", line)
        if chain_m:
            current_chain = chain_m.group(1)
            continue
        # Data rows: pkts bytes target prot opt in out source destination ...
        m = re.match(
            r"^\s+(\d+[KMG]?)\s+(\d+[KMG]?)\s+(DROP|REJECT|ACCEPT|RETURN|LOG|MASQUERADE|SNAT|DNAT)\s+",
            line
        )
        if m and current_chain:
            pkts_str = m.group(1)
            target = m.group(3)
            # Convert K/M/G suffix
            mult = {"K": 1000, "M": 1_000_000, "G": 1_000_000_000}
            pkts = int(pkts_str[:-1]) * mult.get(pkts_str[-1], 1) if pkts_str[-1].isalpha() else int(pkts_str)
            rows.append((current_chain, target, pkts, line.strip()))
    return rows


def check_iptables():
    results = []
    if not command_exists("iptables"):
        results.append(CheckResult(CATEGORY, "iptables", SKIP, "iptables not installed"))
        return results

    stdout, _, rc = run("iptables -L -n -v --line-numbers", sudo=True)
    if rc == -2:
        results.append(CheckResult(CATEGORY, "iptables", SKIP, "Requires sudo"))
        return results
    if rc != 0 or not stdout:
        results.append(CheckResult(CATEGORY, "iptables", INFO, "iptables returned no output or not in use"))
        return results

    rows = _parse_iptables(stdout)
    drop_rules = [(chain, pkts, rule) for chain, target, pkts, rule in rows
                  if target in ("DROP", "REJECT") and pkts > DROP_COUNT_WARN]

    if drop_rules:
        for chain, pkts, rule in drop_rules[:5]:
            results.append(CheckResult(CATEGORY, f"iptables DROP ({chain})", WARN,
                                       f"{pkts} packets dropped: {rule[:100]}",
                                       "Review if this DROP rule is intentional; "
                                       "unexpected high drop counts may indicate misconfiguration"))
    else:
        results.append(CheckResult(CATEGORY, "iptables drops", OK,
                                   "No iptables rules with high DROP/REJECT counts"))

    # Check FORWARD chain default policy
    fwd_m = re.search(r"Chain FORWARD.*policy\s+(\S+)", stdout)
    if fwd_m:
        policy = fwd_m.group(1)
        if policy == "DROP":
            results.append(CheckResult(CATEGORY, "FORWARD policy", INFO,
                                       "FORWARD chain default policy: DROP",
                                       "Expected for non-router; ensure needed forwarding rules are explicit"))
        else:
            results.append(CheckResult(CATEGORY, "FORWARD policy", OK,
                                       f"FORWARD chain policy: {policy}"))

    # Check INPUT chain default policy
    inp_m = re.search(r"Chain INPUT.*policy\s+(\S+)", stdout)
    if inp_m:
        results.append(CheckResult(CATEGORY, "INPUT policy", INFO,
                                   f"INPUT chain default policy: {inp_m.group(1)}"))

    return results


def check_ip6tables():
    results = []
    if not command_exists("ip6tables"):
        return results

    stdout, _, rc = run("ip6tables -L -n -v --line-numbers", sudo=True)
    if rc == -2 or rc != 0 or not stdout:
        return results

    rows = _parse_iptables(stdout)
    drop_rules = [(chain, pkts, rule) for chain, target, pkts, rule in rows
                  if target in ("DROP", "REJECT") and pkts > DROP_COUNT_WARN]

    if drop_rules:
        for chain, pkts, rule in drop_rules[:3]:
            results.append(CheckResult(CATEGORY, f"ip6tables DROP ({chain})", WARN,
                                       f"{pkts} packets dropped: {rule[:100]}",
                                       "Review if this IPv6 DROP rule is intentional"))
    else:
        results.append(CheckResult(CATEGORY, "ip6tables drops", OK,
                                   "No ip6tables rules with high DROP/REJECT counts"))
    return results


def check_nftables():
    results = []
    if not command_exists("nft"):
        return results

    stdout, _, rc = run("nft list ruleset", sudo=True)
    if rc == -2:
        results.append(CheckResult(CATEGORY, "nftables", SKIP, "Requires sudo"))
        return results
    if rc != 0 or not stdout or not stdout.strip():
        results.append(CheckResult(CATEGORY, "nftables", INFO, "No nftables rules configured"))
        return results

    # Count drop/reject statements
    drops = re.findall(r"\b(drop|reject)\b", stdout, re.IGNORECASE)
    if drops:
        results.append(CheckResult(CATEGORY, "nftables", INFO,
                                   f"nftables has {len(drops)} drop/reject statement(s); review manually",
                                   "Run 'nft list ruleset' and review counters"))
    else:
        results.append(CheckResult(CATEGORY, "nftables", OK,
                                   "No drop/reject statements in nftables ruleset"))
    return results


def check_conntrack():
    results = []
    from runner import read_file

    count_str = read_file("/proc/sys/net/netfilter/nf_conntrack_count")
    max_str = read_file("/proc/sys/net/netfilter/nf_conntrack_max")

    if not count_str or not max_str:
        # Try sysctl
        out_c, _, _ = run("sysctl -n net.netfilter.nf_conntrack_count")
        out_m, _, _ = run("sysctl -n net.netfilter.nf_conntrack_max")
        count_str = out_c
        max_str = out_m

    if count_str and max_str:
        try:
            count = int(count_str.strip())
            maximum = int(max_str.strip())
            pct = (count / maximum) * 100 if maximum > 0 else 0

            if pct > CONNTRACK_WARN_PCT:
                results.append(CheckResult(CATEGORY, "Conntrack table", ERROR,
                                           f"conntrack {count}/{maximum} ({pct:.1f}% full)",
                                           "Table near capacity; increase: sysctl -w net.netfilter.nf_conntrack_max="
                                           + str(maximum * 2) + "; or reduce timeout values"))
            elif pct > 60:
                results.append(CheckResult(CATEGORY, "Conntrack table", WARN,
                                           f"conntrack {count}/{maximum} ({pct:.1f}%)",
                                           "Monitor conntrack growth"))
            else:
                results.append(CheckResult(CATEGORY, "Conntrack table", OK,
                                           f"conntrack {count}/{maximum} ({pct:.1f}%)"))
        except ValueError:
            pass
    else:
        results.append(CheckResult(CATEGORY, "Conntrack", INFO,
                                   "conntrack not available (kernel module may not be loaded)"))

    return results


def run_all():
    results = []
    results += check_iptables()
    results += check_ip6tables()
    results += check_nftables()
    results += check_conntrack()
    return results
