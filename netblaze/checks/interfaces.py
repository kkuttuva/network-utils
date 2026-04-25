"""
Interface checks: IP config validity, LAG member pairing, bridge issues, VLANs.
"""
import re
import os
from checks import CheckResult, OK, WARN, ERROR, SKIP, INFO
from runner import run, read_file

CATEGORY = "Interfaces"


def _parse_ifaces():
    """Return dict of {iface: {flags, mtu, state, addrs: [(ip, prefix)]}}"""
    stdout, _, rc = run("ip addr show")
    if rc != 0 or not stdout:
        return {}

    ifaces = {}
    current = None
    for line in stdout.splitlines():
        m = re.match(r"^\d+:\s+(\S+):\s+<([^>]*)>.*mtu\s+(\d+).*state\s+(\S+)", line)
        if m:
            current = m.group(1).rstrip("@").split("@")[0]
            ifaces[current] = {
                "flags": m.group(2).split(","),
                "mtu": int(m.group(3)),
                "state": m.group(4),
                "addrs": [],
            }
        elif current:
            ip_m = re.match(r"\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
            if ip_m:
                ifaces[current]["addrs"].append((ip_m.group(1), int(ip_m.group(2))))
    return ifaces


def check_ip_config_validity():
    results = []
    ifaces = _parse_ifaces()

    for iface, info in ifaces.items():
        if iface == "lo":
            continue
        for ip, prefix in info["addrs"]:
            if prefix == 32 and iface != "lo":
                results.append(CheckResult(CATEGORY, f"IP mask ({iface})", WARN,
                                           f"{ip}/{prefix} — /32 host route on non-loopback",
                                           "Verify this is intentional (point-to-point link or VPN)"))
            elif prefix == 0:
                results.append(CheckResult(CATEGORY, f"IP mask ({iface})", ERROR,
                                           f"{ip}/{prefix} — /0 mask is invalid",
                                           "Fix subnet mask; /0 means no subnetting at all"))
            elif prefix > 30:
                results.append(CheckResult(CATEGORY, f"IP mask ({iface})", WARN,
                                           f"{ip}/{prefix} — very small subnet (/{prefix})",
                                           "Confirm this is intentional"))
            else:
                results.append(CheckResult(CATEGORY, f"IP config ({iface})", OK,
                                           f"{ip}/{prefix}"))

        # Check same subnet on multiple addresses on same interface
        nets = []
        for ip, prefix in info["addrs"]:
            import ipaddress
            try:
                net = str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
                if net in nets:
                    results.append(CheckResult(CATEGORY, f"Duplicate subnet ({iface})", WARN,
                                               f"Multiple IPs in same subnet {net}",
                                               "Remove duplicate; may cause routing ambiguity"))
                else:
                    nets.append(net)
            except ValueError:
                pass

    if not any(i for i in ifaces if i != "lo"):
        results.append(CheckResult(CATEGORY, "Interfaces", ERROR,
                                   "No non-loopback interfaces with IPs found",
                                   "Check network configuration"))
    return results


def check_lag_members():
    results = []
    bond_dir = "/proc/net/bonding"
    if not os.path.isdir(bond_dir):
        return results

    try:
        bonds = os.listdir(bond_dir)
    except Exception:
        return results

    ifaces = _parse_ifaces()

    for bond in bonds:
        content = read_file(f"{bond_dir}/{bond}")
        if not content:
            continue

        # Check if bond master has an IP (not slave interface)
        slaves = re.findall(r"Slave Interface:\s*(\S+)", content)
        for slave in slaves:
            if slave in ifaces and ifaces[slave]["addrs"]:
                results.append(CheckResult(CATEGORY, f"LAG member IP ({slave})", ERROR,
                                           f"Slave {slave} has IP address assigned directly",
                                           f"Remove IP from slave; assign IP to bond master {bond} instead"))
            else:
                results.append(CheckResult(CATEGORY, f"LAG member ({slave})", OK,
                                           f"Slave {slave} has no standalone IP (correct)"))

        # Speed mismatch between slaves via ethtool
        speeds = {}
        for slave in slaves:
            stdout, _, rc = run(f"ethtool {slave}")
            if rc == 0 and stdout:
                sm = re.search(r"Speed:\s*(\S+)", stdout)
                if sm:
                    speeds[slave] = sm.group(1)

        unique_speeds = set(speeds.values())
        if len(unique_speeds) > 1:
            results.append(CheckResult(CATEGORY, f"LAG speed mismatch ({bond})", WARN,
                                       f"Slaves have different speeds: {speeds}",
                                       "All LAG members must run at the same speed"))
        elif speeds:
            results.append(CheckResult(CATEGORY, f"LAG speeds ({bond})", OK,
                                       f"All slaves at same speed: {list(unique_speeds)[0]}"))

    return results


def check_bridge_issues():
    results = []
    stdout, _, rc = run("ip link show type bridge")
    if rc != 0 or not stdout:
        # Try brctl
        stdout2, _, rc2 = run("brctl show")
        if rc2 != 0 or not stdout2 or stdout2.strip() == "bridge name\tbridge id\t\tSTP enabled\tinterfaces":
            results.append(CheckResult(CATEGORY, "Bridges", INFO, "No bridge interfaces found"))
            return results

        # Parse brctl output
        lines = stdout2.strip().splitlines()[1:]
        bridge = None
        for line in lines:
            parts = line.split()
            if len(parts) >= 4:
                bridge = parts[0]
                iface = parts[3] if len(parts) > 3 else None
                if iface:
                    results.append(CheckResult(CATEGORY, f"Bridge ({bridge})", OK,
                                               f"Has member interface: {iface}"))
                else:
                    results.append(CheckResult(CATEGORY, f"Bridge ({bridge})", WARN,
                                               "Bridge has no member interfaces",
                                               "Add at least one physical/veth interface to the bridge"))
            elif bridge and parts:
                # continuation line with just interface name
                pass
        return results

    # ip link show type bridge
    bridges = re.findall(r"^\d+:\s+(\S+):", stdout, re.MULTILINE)
    for br in bridges:
        # Check for member ports
        stdout3, _, _ = run(f"ip link show master {br}")
        if not stdout3 or not stdout3.strip():
            results.append(CheckResult(CATEGORY, f"Bridge ({br})", WARN,
                                       "Bridge has no member interfaces (no ports enslaved)",
                                       "Enslave at least one interface: ip link set <iface> master " + br))
        else:
            members = re.findall(r"^\d+:\s+(\S+):", stdout3, re.MULTILINE)
            results.append(CheckResult(CATEGORY, f"Bridge ({br})", OK,
                                       f"Members: {', '.join(members)}"))

        # Check STP state
        stp_file = f"/sys/class/net/{br}/bridge/stp_state"
        stp = read_file(stp_file)
        if stp and stp.strip() == "0":
            results.append(CheckResult(CATEGORY, f"Bridge STP ({br})", INFO,
                                       "STP disabled on bridge",
                                       "Enable STP if this bridge connects multiple network segments to avoid loops"))

    return results


def check_vlan_issues():
    results = []
    stdout, _, rc = run("ip link show type vlan")
    if rc != 0 or not stdout or not stdout.strip():
        results.append(CheckResult(CATEGORY, "VLANs", INFO, "No VLAN interfaces found"))
        return results

    ifaces = _parse_ifaces()

    for line in stdout.splitlines():
        m = re.match(r"^\d+:\s+(\S+)@(\S+):", line)
        if m:
            vlan_iface = m.group(1)
            parent = m.group(2)
            if parent in ifaces:
                parent_state = ifaces[parent].get("state", "unknown")
                if parent_state.upper() == "DOWN":
                    results.append(CheckResult(CATEGORY, f"VLAN parent ({vlan_iface})", ERROR,
                                               f"Parent interface {parent} is DOWN",
                                               f"Bring up parent: ip link set {parent} up"))
                else:
                    results.append(CheckResult(CATEGORY, f"VLAN ({vlan_iface})", OK,
                                               f"Parent {parent} is {parent_state}"))
            else:
                results.append(CheckResult(CATEGORY, f"VLAN parent ({vlan_iface})", WARN,
                                           f"Parent {parent} not found in interface list"))

    return results


def check_promisc_and_down():
    results = []
    stdout, _, rc = run("ip link show")
    if rc != 0 or not stdout:
        return results

    for line in stdout.splitlines():
        m = re.match(r"^\d+:\s+(\S+):\s+<([^>]*)>", line)
        if not m:
            continue
        iface = m.group(1).rstrip(":").split("@")[0]
        flags = m.group(2).upper()
        if iface == "lo":
            continue

        flag_list = flags.split(",")
        is_up = "UP" in flag_list
        has_lower_up = "LOWER_UP" in flag_list
        is_promisc = "PROMISC" in flag_list

        if is_up and not has_lower_up:
            results.append(CheckResult(CATEGORY, f"Carrier ({iface})", WARN,
                                       "Interface UP but no carrier (LOWER_UP missing)",
                                       "Check physical cable or switch port"))

        if is_promisc:
            results.append(CheckResult(CATEGORY, f"Promiscuous ({iface})", WARN,
                                       "PROMISC flag set",
                                       "Verify this is expected (bridge member, packet capture, VM host); "
                                       "unexpected promiscuous mode may indicate a sniffer"))

    return results


def run_all():
    results = []
    results += check_ip_config_validity()
    results += check_lag_members()
    results += check_bridge_issues()
    results += check_vlan_issues()
    results += check_promisc_and_down()
    return results
