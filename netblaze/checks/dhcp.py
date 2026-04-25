"""
DHCP checks: lease validity, client running, server conflicts, slave-vs-master assignment.
"""
import re
import os
import time
from checks import CheckResult, OK, WARN, ERROR, SKIP, INFO
from runner import run, read_file, command_exists

CATEGORY = "DHCP"

LEASE_EXPIRY_WARN_SECS = 3600   # warn if lease expires in < 1 hour


def _parse_dhclient_lease(content):
    """Parse dhclient lease file, return list of lease dicts."""
    leases = []
    blocks = re.findall(r"lease\s*\{([^}]+)\}", content, re.DOTALL)
    for block in blocks:
        lease = {}
        for key, pattern in [
            ("interface", r'interface\s+"([^"]+)"'),
            ("fixed_address", r"fixed-address\s+(\S+);"),
            ("expire", r"expire\s+\d+\s+([\d/]+\s+[\d:]+);"),
            ("renew", r"renew\s+\d+\s+([\d/]+\s+[\d:]+);"),
        ]:
            m = re.search(pattern, block)
            if m:
                lease[key] = m.group(1)
        leases.append(lease)
    return leases


def _parse_lease_time(time_str):
    """Parse 'YYYY/MM/DD HH:MM:SS' to epoch. Returns None on failure."""
    try:
        import datetime
        dt = datetime.datetime.strptime(time_str.strip(), "%Y/%m/%d %H:%M:%S")
        return dt.timestamp()
    except Exception:
        return None


def check_dhcp_leases():
    results = []
    lease_files = [
        "/var/lib/dhclient/dhclient.leases",
        "/var/lib/dhclient.leases",
        "/var/lib/NetworkManager/dhclient-*.lease",
    ]

    # Also try dhcpcd
    dhcpcd_dirs = ["/var/lib/dhcpcd", "/var/lib/dhcpcd5"]

    found_any = False
    for path in lease_files:
        # Handle glob pattern
        if "*" in path:
            import glob
            matches = glob.glob(path)
        else:
            matches = [path] if os.path.exists(path) else []

        for filepath in matches:
            content = read_file(filepath)
            if not content:
                continue
            found_any = True
            leases = _parse_dhclient_lease(content)
            if not leases:
                continue

            # Use the last (most recent) lease
            lease = leases[-1]
            iface = lease.get("interface", "unknown")
            ip = lease.get("fixed_address", "unknown")
            expire_str = lease.get("expire")

            if expire_str and expire_str.strip() != "never":
                expire_epoch = _parse_lease_time(expire_str)
                if expire_epoch:
                    now = time.time()
                    remaining = expire_epoch - now
                    if remaining < 0:
                        results.append(CheckResult(CATEGORY, f"Lease ({iface})", ERROR,
                                                   f"DHCP lease for {ip} on {iface} has EXPIRED",
                                                   "Release and renew: dhclient -r " + iface + " && dhclient " + iface))
                    elif remaining < LEASE_EXPIRY_WARN_SECS:
                        results.append(CheckResult(CATEGORY, f"Lease ({iface})", WARN,
                                                   f"Lease {ip} expires in {int(remaining//60)} minutes",
                                                   "Renew: dhclient " + iface))
                    else:
                        results.append(CheckResult(CATEGORY, f"Lease ({iface})", OK,
                                                   f"Lease {ip} on {iface}, expires in "
                                                   f"{int(remaining//3600)}h {int((remaining%3600)//60)}m"))
            else:
                results.append(CheckResult(CATEGORY, f"Lease ({iface})", OK,
                                           f"Lease {ip} on {iface} (never expires or static)"))

    # NetworkManager DHCP status
    if not found_any and command_exists("nmcli"):
        stdout, _, rc = run("nmcli -t -f DEVICE,STATE,IP4 device")
        if rc == 0 and stdout:
            for line in stdout.splitlines():
                parts = line.split(":")
                if len(parts) >= 2 and parts[1].strip() == "connected":
                    found_any = True
                    results.append(CheckResult(CATEGORY, f"NM lease ({parts[0]})", OK,
                                               f"NetworkManager: {parts[0]} connected"))

    if not found_any:
        results.append(CheckResult(CATEGORY, "DHCP leases", INFO,
                                   "No DHCP lease files found (host may use static IPs or NM)"))
    return results


def check_dhcp_client_service():
    results = []
    services = ["NetworkManager", "dhclient", "dhcpcd", "systemd-networkd"]

    # Check if any dynamic interfaces exist
    stdout, _, rc = run("ip addr show")
    has_dynamic = False
    if stdout:
        has_dynamic = "dynamic" in stdout

    if not has_dynamic:
        results.append(CheckResult(CATEGORY, "DHCP client", INFO,
                                   "No dynamic (DHCP) interfaces detected; host may use static IPs"))
        return results

    any_active = False
    for svc in services:
        out, _, rc = run(f"systemctl is-active {svc}")
        if out and out.strip() == "active":
            results.append(CheckResult(CATEGORY, f"DHCP client ({svc})", OK,
                                       f"{svc} is active"))
            any_active = True

    if not any_active and has_dynamic:
        results.append(CheckResult(CATEGORY, "DHCP client service", ERROR,
                                   "Dynamic interface detected but no DHCP client service is active",
                                   "Start DHCP client: systemctl start NetworkManager or dhclient <iface>"))
    return results


def check_dhcp_server_conflicts():
    results = []
    if not command_exists("journalctl"):
        return results

    stdout, _, rc = run("journalctl -n 500 --no-pager -q --grep='DHCP'", sudo=True, timeout=15)
    if rc == -2:
        results.append(CheckResult(CATEGORY, "DHCP conflicts (journal)", SKIP, "Requires sudo"))
        return results
    if rc != 0 or not stdout:
        return results

    no_offer = re.findall(r"No DHCPOFFERS received|no offers", stdout, re.IGNORECASE)
    nak = re.findall(r"DHCPNAK|received NAK", stdout, re.IGNORECASE)
    decline = re.findall(r"DHCPDECLINE|address.*in use", stdout, re.IGNORECASE)

    if no_offer:
        results.append(CheckResult(CATEGORY, "DHCP offers", ERROR,
                                   f"{len(no_offer)} 'No DHCPOFFERS received' event(s) in journal",
                                   "DHCP server unreachable; check L2 connectivity, "
                                   "VLAN config, and that DHCP server is running"))
    if nak:
        results.append(CheckResult(CATEGORY, "DHCP NAK", WARN,
                                   f"{len(nak)} DHCP NAK event(s) in journal",
                                   "Server rejected lease request; "
                                   "check for IP pool exhaustion or stale lease"))
    if decline:
        results.append(CheckResult(CATEGORY, "DHCP DECLINE", WARN,
                                   f"{len(decline)} DHCP DECLINE event(s) — address conflict detected",
                                   "Another host has the offered IP; "
                                   "check for duplicate IP addresses on the network segment"))

    if not no_offer and not nak and not decline:
        results.append(CheckResult(CATEGORY, "DHCP server", OK,
                                   "No DHCP errors in recent journal"))
    return results


def check_slave_dhcp():
    """Detect DHCP on a bonding slave instead of the master."""
    results = []
    import os
    bond_dir = "/proc/net/bonding"
    if not os.path.isdir(bond_dir):
        return results

    try:
        bonds = os.listdir(bond_dir)
    except Exception:
        return results

    stdout, _, rc = run("ip addr show")
    if rc != 0 or not stdout:
        return results

    for bond in bonds:
        content = read_file(f"{bond_dir}/{bond}")
        if not content:
            continue
        slaves = re.findall(r"Slave Interface:\s*(\S+)", content)
        for slave in slaves:
            if f" {slave}:" in stdout or f"\n{slave}:" in stdout:
                # Check if slave has an IP
                slave_block = re.search(
                    rf"(?:^|\n)\d+:\s+{re.escape(slave)}:.*?(?=\n\d+:|\Z)",
                    stdout, re.DOTALL
                )
                if slave_block and "inet " in slave_block.group(0):
                    results.append(CheckResult(CATEGORY, f"DHCP on slave ({slave})", ERROR,
                                               f"Slave interface {slave} has IP (should be on bond master {bond})",
                                               f"Remove IP from {slave}; configure DHCP on {bond} instead"))

    return results


def run_all():
    results = []
    results += check_dhcp_leases()
    results += check_dhcp_client_service()
    results += check_dhcp_server_conflicts()
    results += check_slave_dhcp()
    return results
