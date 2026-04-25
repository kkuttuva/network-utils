"""
IP configuration checks: duplicate IPs, MTU mismatches, path MTU, gateway ARP, routing.
"""
import re
import ipaddress
from checks import CheckResult, OK, WARN, ERROR, SKIP, INFO
from runner import run, command_exists

CATEGORY = "IP Config"


def _get_default_gateway():
    stdout, _, rc = run("ip route show default")
    if rc != 0 or not stdout:
        return None
    m = re.search(r"default via (\S+)", stdout)
    return m.group(1) if m else None


def check_duplicate_ips():
    results = []
    if not command_exists("arping"):
        results.append(CheckResult(CATEGORY, "Duplicate IPs", SKIP,
                                   "arping not installed", "Install arping (iputils-arping)"))
        return results

    stdout, _, rc = run("ip addr show")
    if rc != 0 or not stdout:
        return results

    ips_ifaces = re.findall(r"inet (\d+\.\d+\.\d+\.\d+)/\d+.*?(?:global|dynamic)\s+(\S+)", stdout)
    for ip, iface in ips_ifaces:
        if ip.startswith("127."):
            continue
        out, _, rc = run(f"arping -D -c 2 -I {iface} {ip}", sudo=True, timeout=8)
        if rc == -2:
            results.append(CheckResult(CATEGORY, f"Duplicate IP ({ip})", SKIP, "Requires sudo"))
            continue
        # arping -D exits 1 if duplicate found
        if rc == 1:
            results.append(CheckResult(CATEGORY, f"Duplicate IP ({ip})", ERROR,
                                       f"Duplicate IP {ip} detected on {iface}",
                                       "Another host is using this IP; investigate with 'arping -c 3 " + ip + "'"))
        else:
            results.append(CheckResult(CATEGORY, f"Duplicate IP ({ip})", OK,
                                       f"No duplicate for {ip} on {iface}"))
    return results


def check_mtu_mismatches():
    results = []
    stdout, _, rc = run("ip link show")
    if rc != 0 or not stdout:
        return results

    mtus = {}
    for line in stdout.splitlines():
        m = re.match(r"^\d+:\s+(\S+).*mtu\s+(\d+)", line)
        if m:
            iface = m.group(1).rstrip(":").split("@")[0]
            if iface != "lo":
                mtus[iface] = int(m.group(2))

    # Check bonding slave MTU consistency
    import os
    bond_dir = "/proc/net/bonding"
    if os.path.isdir(bond_dir):
        try:
            bonds = os.listdir(bond_dir)
        except Exception:
            bonds = []
        for bond in bonds:
            from runner import read_file
            content = read_file(f"{bond_dir}/{bond}")
            if content:
                slaves = re.findall(r"Slave Interface:\s*(\S+)", content)
                slave_mtus = {s: mtus.get(s) for s in slaves if s in mtus}
                bond_mtu = mtus.get(bond)
                all_mtus = list(slave_mtus.values()) + ([bond_mtu] if bond_mtu else [])
                if len(set(filter(None, all_mtus))) > 1:
                    results.append(CheckResult(CATEGORY, f"MTU mismatch ({bond})", WARN,
                                               f"MTU inconsistency: bond={bond_mtu}, slaves={slave_mtus}",
                                               "Set all members to same MTU; usually match bond master"))
                elif all_mtus:
                    results.append(CheckResult(CATEGORY, f"MTU ({bond})", OK,
                                               f"Consistent MTU={all_mtus[0]} across bond and slaves"))

    # Report MTU for physical interfaces
    physical_mtus = {k: v for k, v in mtus.items()
                     if not k.startswith("bond") and not k.startswith("br") and not k.startswith("veth")}
    unique_mtus = set(physical_mtus.values())
    if len(unique_mtus) > 1:
        results.append(CheckResult(CATEGORY, "MTU mismatch (physical)", WARN,
                                   f"Physical interfaces have different MTUs: {physical_mtus}",
                                   "Ensure MTUs are intentionally different (e.g. jumbo frames on storage iface)"))
    elif physical_mtus:
        mtu_val = list(unique_mtus)[0]
        status = OK
        rec = ""
        if mtu_val < 1500:
            status = WARN
            rec = "MTU below standard 1500; verify this is intentional"
        results.append(CheckResult(CATEGORY, "MTU (physical)", status,
                                   f"MTU={mtu_val} on physical interfaces", rec))

    return results


def check_path_mtu():
    results = []
    gw = _get_default_gateway()
    if not gw:
        results.append(CheckResult(CATEGORY, "Path MTU", SKIP, "No default gateway to test path MTU"))
        return results

    if command_exists("tracepath"):
        stdout, _, rc = run(f"tracepath -n {gw}", timeout=15)
        if rc == 0 and stdout:
            pmtu_m = re.search(r"pmtu\s+(\d+)", stdout)
            if pmtu_m:
                pmtu = int(pmtu_m.group(1))
                if pmtu < 1500:
                    results.append(CheckResult(CATEGORY, "Path MTU", WARN,
                                               f"Path MTU to gateway {gw} is {pmtu} (less than 1500)",
                                               "PMTU below 1500 may cause fragmentation; "
                                               "ensure 'ip tcp_adjust_mss' is set on routers"))
                else:
                    results.append(CheckResult(CATEGORY, "Path MTU", OK,
                                               f"Path MTU to gateway {gw}: {pmtu}"))
            else:
                results.append(CheckResult(CATEGORY, "Path MTU", INFO,
                                           f"tracepath to {gw} completed but no PMTU found"))
    else:
        # ping with DF bit
        stdout, _, rc = run(f"ping -c 1 -M do -s 1472 {gw}", timeout=5)
        if rc != 0 and stdout and "Frag needed" in stdout:
            results.append(CheckResult(CATEGORY, "Path MTU", WARN,
                                       "Fragmentation needed but DF set to gateway",
                                       "PMTU discovery may be blocked; check ICMP type 3 code 4 is not firewalled"))
        elif rc == 0:
            results.append(CheckResult(CATEGORY, "Path MTU", OK,
                                       f"1500-byte ping to gateway {gw} succeeded (no fragmentation)"))
        else:
            results.append(CheckResult(CATEGORY, "Path MTU", INFO,
                                       f"Could not complete PMTU test to {gw}"))

    return results


def check_default_gateway():
    results = []
    gw = _get_default_gateway()

    if not gw:
        results.append(CheckResult(CATEGORY, "Default gateway", ERROR,
                                   "No default route configured",
                                   "Add default route: ip route add default via <gateway_ip> dev <iface>"))
        return results

    results.append(CheckResult(CATEGORY, "Default gateway", OK, f"Default gateway: {gw}"))

    # Check ARP entry for gateway
    stdout, _, rc = run("ip neigh show")
    if rc == 0 and stdout:
        gw_entries = [l for l in stdout.splitlines() if l.startswith(gw + " ") or f" {gw} " in l.split("lladdr")[0]]
        if not gw_entries:
            # Try to ping and see if ARP resolves
            run(f"ping -c 1 -W 2 {gw}", timeout=5)
            stdout2, _, _ = run("ip neigh show")
            gw_entries = [l for l in (stdout2 or "").splitlines()
                          if l.startswith(gw + " ") or f" {gw} " in l.split("lladdr")[0]]

        if gw_entries:
            entry = gw_entries[0]
            if "FAILED" in entry:
                results.append(CheckResult(CATEGORY, f"Gateway ARP ({gw})", ERROR,
                                           f"ARP FAILED for gateway {gw}",
                                           "Gateway unreachable; check L2 connectivity and gateway status"))
            elif "INCOMPLETE" in entry:
                results.append(CheckResult(CATEGORY, f"Gateway ARP ({gw})", WARN,
                                           f"ARP INCOMPLETE for gateway {gw}",
                                           "Gateway ARP not resolved; intermittent L2 issue"))
            elif "lladdr" in entry:
                mac_m = re.search(r"lladdr\s+(\S+)", entry)
                mac = mac_m.group(1) if mac_m else "unknown"
                results.append(CheckResult(CATEGORY, f"Gateway ARP ({gw})", OK,
                                           f"Gateway ARP resolved: {gw} -> {mac}"))
        else:
            results.append(CheckResult(CATEGORY, f"Gateway ARP ({gw})", WARN,
                                       f"No ARP entry for gateway {gw}",
                                       "Gateway may be unreachable; run 'ping " + gw + "' to verify"))

    return results


def check_ip_forwarding():
    results = []
    from runner import read_file
    fwd = read_file("/proc/sys/net/ipv4/ip_forward")
    if fwd:
        val = fwd.strip()
        if val == "1":
            results.append(CheckResult(CATEGORY, "IP forwarding", INFO,
                                       "IP forwarding is ENABLED (host acts as router/gateway)",
                                       "Disable if this is not a router: sysctl -w net.ipv4.ip_forward=0"))
        else:
            results.append(CheckResult(CATEGORY, "IP forwarding", OK,
                                       "IP forwarding disabled (normal for end-host)"))
    return results


def check_blackhole_routes():
    results = []
    stdout, _, rc = run("ip route show")
    if rc != 0 or not stdout:
        return results

    for line in stdout.splitlines():
        if re.search(r"\b(blackhole|unreachable|prohibit)\b", line):
            results.append(CheckResult(CATEGORY, "Blackhole route", WARN,
                                       f"Special route: {line.strip()}",
                                       "Verify this route is intentional"))
    return results


def run_all():
    results = []
    results += check_duplicate_ips()
    results += check_mtu_mismatches()
    results += check_path_mtu()
    results += check_default_gateway()
    results += check_ip_forwarding()
    results += check_blackhole_routes()
    return results
