"""
Ethernet layer checks: drivers, CRC errors, duplex, LAG/LACP, ARP, ring buffers.
"""
import re
from checks import CheckResult, OK, WARN, ERROR, SKIP, INFO
from runner import run, read_file, command_exists

CATEGORY = "Ethernet"


def _get_interfaces():
    stdout, _, rc = run("ip link show")
    if rc != 0 or not stdout:
        return []
    ifaces = re.findall(r"^\d+:\s+(\S+):", stdout, re.MULTILINE)
    return [i.rstrip(":") for i in ifaces if i not in ("lo",)]


def check_driver_errors():
    results = []
    stdout, _, rc = run("dmesg")
    if rc != 0 or stdout is None:
        results.append(CheckResult(CATEGORY, "Driver/dmesg", SKIP, "dmesg not available"))
        return results

    patterns = [
        (r"(eth\w+|ens\w+|enp\w+).*(error|fail|reset|firmware)", ERROR, "Driver error in dmesg"),
        (r"(eth\w+|ens\w+|enp\w+).*NIC Link is Down", WARN, "NIC link down event in dmesg"),
        (r"(NETDEV WATCHDOG|transmit queue.*timed out)", ERROR, "TX watchdog timeout in dmesg"),
    ]
    found_any = False
    for pattern, status, label in patterns:
        matches = re.findall(pattern, stdout, re.IGNORECASE)
        if matches:
            found_any = True
            sample = str(matches[0])[:80]
            results.append(CheckResult(CATEGORY, "Driver errors", status, f"{label}: ...{sample}...",
                                       "Check 'dmesg | grep -i eth' for full context; update driver/firmware"))
    if not found_any:
        results.append(CheckResult(CATEGORY, "Driver errors", OK, "No driver errors in dmesg"))
    return results


def check_crc_errors():
    results = []
    ifaces = _get_interfaces()
    if not ifaces:
        results.append(CheckResult(CATEGORY, "CRC errors", SKIP, "No interfaces found"))
        return results

    for iface in ifaces:
        if not command_exists("ethtool"):
            results.append(CheckResult(CATEGORY, f"CRC ({iface})", SKIP,
                                       "ethtool not installed", "Install ethtool"))
            break

        stdout, _, rc = run(f"ethtool -S {iface}", sudo=True)
        if rc == -2:
            results.append(CheckResult(CATEGORY, f"CRC ({iface})", SKIP, "Requires sudo"))
            continue
        if rc != 0 or not stdout:
            # Try ip -s link fallback
            stdout2, _, _ = run(f"ip -s link show {iface}")
            if stdout2:
                errors = re.search(r"RX.*\n\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", stdout2)
                if errors:
                    rx_err = int(errors.group(2))
                    if rx_err > 0:
                        results.append(CheckResult(CATEGORY, f"CRC ({iface})", WARN,
                                                   f"ip -s link RX errors: {rx_err}",
                                                   "Check cable/SFP; run ethtool -S for detail"))
                    else:
                        results.append(CheckResult(CATEGORY, f"CRC ({iface})", OK, "No RX errors (ip -s link)"))
            continue

        crc_keys = ["rx_crc_errors", "rx_frame_errors", "rx_errors", "bad_fcs"]
        found_crc = False
        for line in stdout.splitlines():
            for key in crc_keys:
                if key in line.lower():
                    m = re.search(r":\s*(\d+)", line)
                    if m and int(m.group(1)) > 0:
                        found_crc = True
                        results.append(CheckResult(CATEGORY, f"CRC ({iface})", ERROR,
                                                   f"{line.strip()}",
                                                   "Check physical layer: cable, SFP/GBIC, patch panel, switch port"))
        if not found_crc:
            results.append(CheckResult(CATEGORY, f"CRC ({iface})", OK, "No CRC/frame errors"))
    return results


def check_tx_drops():
    results = []
    stdout, _, rc = run("ip -s link")
    if rc != 0 or not stdout:
        results.append(CheckResult(CATEGORY, "TX drops", SKIP, "ip -s link failed"))
        return results

    current_iface = None
    lines = stdout.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^\d+:\s+(\S+):", line)
        if m:
            current_iface = m.group(1).rstrip(":")
            continue
        if current_iface and current_iface != "lo" and "TX:" in line and i + 1 < len(lines):
            tx_line = lines[i + 1].strip().split()
            if len(tx_line) >= 5:
                try:
                    dropped = int(tx_line[3])
                    overrun = int(tx_line[4])
                    if dropped > 0 or overrun > 0:
                        results.append(CheckResult(CATEGORY, f"TX drops ({current_iface})", WARN,
                                                   f"TX dropped={dropped}, overrun={overrun}",
                                                   "Increase tx queue len: ip link set txqueuelen 10000 dev " + current_iface))
                    else:
                        results.append(CheckResult(CATEGORY, f"TX drops ({current_iface})", OK,
                                                   "No TX drops or overruns"))
                except (ValueError, IndexError):
                    pass
    return results


def check_duplex():
    results = []
    ifaces = _get_interfaces()
    for iface in ifaces:
        if not command_exists("ethtool"):
            results.append(CheckResult(CATEGORY, f"Duplex ({iface})", SKIP,
                                       "ethtool not installed"))
            break
        stdout, _, rc = run(f"ethtool {iface}")
        if rc != 0 or not stdout:
            continue
        duplex_m = re.search(r"Duplex:\s*(\S+)", stdout)
        speed_m = re.search(r"Speed:\s*(\S+)", stdout)
        link_m = re.search(r"Link detected:\s*(\S+)", stdout)

        if link_m and link_m.group(1).lower() == "no":
            results.append(CheckResult(CATEGORY, f"Duplex ({iface})", WARN,
                                       "Link not detected", "Check cable and switch port"))
            continue

        if duplex_m:
            duplex = duplex_m.group(1)
            speed = speed_m.group(1) if speed_m else "Unknown"
            if duplex.lower() == "half":
                results.append(CheckResult(CATEGORY, f"Duplex ({iface})", ERROR,
                                           f"Half-duplex detected (speed={speed})",
                                           f"Force full-duplex: ethtool -s {iface} duplex full; check switch port config"))
            elif duplex.lower() in ("unknown", ""):
                results.append(CheckResult(CATEGORY, f"Duplex ({iface})", WARN,
                                           f"Duplex unknown (speed={speed})",
                                           "May indicate auto-negotiation failure"))
            else:
                results.append(CheckResult(CATEGORY, f"Duplex ({iface})", OK,
                                           f"{duplex}-duplex at {speed}"))
        else:
            results.append(CheckResult(CATEGORY, f"Duplex ({iface})", INFO,
                                       "ethtool duplex info not available (may be virtual/wifi)"))
    return results


def check_lag_lacp():
    results = []
    bond_dir = "/proc/net/bonding"
    import os
    if not os.path.isdir(bond_dir):
        results.append(CheckResult(CATEGORY, "LAG/LACP", INFO, "No bonding interfaces found"))
        return results

    try:
        bonds = os.listdir(bond_dir)
    except Exception:
        bonds = []

    if not bonds:
        results.append(CheckResult(CATEGORY, "LAG/LACP", INFO, "No bonding interfaces found"))
        return results

    for bond in bonds:
        content = read_file(f"{bond_dir}/{bond}")
        if not content:
            continue

        mode_m = re.search(r"Bonding Mode:\s*(.+)", content)
        mode = mode_m.group(1).strip() if mode_m else "unknown"

        # Check LACP if mode 4
        if "802.3ad" in mode or "lacp" in mode.lower():
            lacp_rate_m = re.search(r"LACP rate:\s*(\S+)", content)
            lacp_rate = lacp_rate_m.group(1) if lacp_rate_m else "unknown"

            # Check each slave for LACP errors via ethtool
            slaves = re.findall(r"Slave Interface:\s*(\S+)", content)
            for slave in slaves:
                stdout, _, rc = run(f"ethtool -S {slave}", sudo=True)
                if rc == 0 and stdout:
                    lacp_errs = {}
                    for key in ["lacp_rx_errors", "lacp_tx_errors", "lacp_unknown_rx", "lacp_illegal_rx"]:
                        m = re.search(rf"{key}:\s*(\d+)", stdout)
                        if m and int(m.group(1)) > 0:
                            lacp_errs[key] = int(m.group(1))
                    if lacp_errs:
                        results.append(CheckResult(CATEGORY, f"LACP errors ({slave})", ERROR,
                                                   str(lacp_errs),
                                                   "Check switch LACP config; verify LACP rate matches on both ends"))
                    else:
                        results.append(CheckResult(CATEGORY, f"LACP ({slave})", OK, f"No LACP errors (rate={lacp_rate})"))

        # Check MII status of slaves
        slave_blocks = re.findall(r"Slave Interface:.*?(?=Slave Interface:|$)", content, re.DOTALL)
        for block in slave_blocks:
            slave_m = re.search(r"Slave Interface:\s*(\S+)", block)
            mii_m = re.search(r"MII Status:\s*(\S+)", block)
            if slave_m and mii_m:
                slave_name = slave_m.group(1)
                mii_status = mii_m.group(1)
                if mii_status.lower() != "up":
                    results.append(CheckResult(CATEGORY, f"LAG slave ({slave_name})", ERROR,
                                               f"MII Status: {mii_status}",
                                               "Check physical connection and switch port for this slave"))
                else:
                    results.append(CheckResult(CATEGORY, f"LAG slave ({slave_name})", OK,
                                               f"MII Status: up (bond={bond}, mode={mode})"))

        # Check speed mismatch between slaves
        speeds = re.findall(r"Speed:\s*(\d+)", content)
        if len(set(speeds)) > 1:
            results.append(CheckResult(CATEGORY, f"LAG speed mismatch ({bond})", WARN,
                                       f"Slave speeds differ: {speeds}",
                                       "All LAG members should operate at the same speed"))

    return results


def check_collisions():
    results = []
    stdout, _, rc = run("ip -s link")
    if rc != 0 or not stdout:
        return results

    # Parse collisions from ip -s link output
    iface = None
    for line in stdout.splitlines():
        m = re.match(r"^\d+:\s+(\S+):", line)
        if m:
            iface = m.group(1).rstrip(":")
        if iface and iface != "lo":
            col_m = re.search(r"collisions\s+(\d+)", line)
            if col_m:
                colls = int(col_m.group(1))
                if colls > 0:
                    results.append(CheckResult(CATEGORY, f"Collisions ({iface})", ERROR,
                                               f"{colls} collisions detected on full-duplex interface",
                                               "Collisions on full-duplex indicate duplex mismatch; check switch config"))
    return results


def check_invalid_macs():
    results = []
    stdout, _, rc = run("ip link show")
    if rc != 0 or not stdout:
        return results

    iface = None
    for line in stdout.splitlines():
        m = re.match(r"^\d+:\s+(\S+):", line)
        if m:
            iface = m.group(1).rstrip(":")
            continue
        mac_m = re.search(r"link/ether\s+([0-9a-f:]{17})", line)
        if mac_m and iface and iface != "lo":
            mac = mac_m.group(1)
            first_byte = int(mac.split(":")[0], 16)
            if mac == "00:00:00:00:00:00":
                results.append(CheckResult(CATEGORY, f"MAC ({iface})", ERROR,
                                           f"All-zero MAC: {mac}",
                                           "Interface may not be initialized properly"))
            elif mac.upper() == "FF:FF:FF:FF:FF:FF":
                results.append(CheckResult(CATEGORY, f"MAC ({iface})", ERROR,
                                           f"Broadcast MAC: {mac}",
                                           "Invalid unicast MAC address"))
            elif first_byte & 0x01:
                results.append(CheckResult(CATEGORY, f"MAC ({iface})", ERROR,
                                           f"Multicast bit set in source MAC: {mac}",
                                           "Interface has invalid MAC; check NIC firmware or driver"))
            else:
                results.append(CheckResult(CATEGORY, f"MAC ({iface})", OK, f"MAC: {mac}"))
    return results


def check_arp_failures():
    results = []
    stdout, _, rc = run("ip neigh show")
    if rc != 0 or not stdout:
        results.append(CheckResult(CATEGORY, "ARP failures", SKIP, "ip neigh failed"))
        return results

    failed = []
    incomplete = []
    for line in stdout.splitlines():
        if "FAILED" in line:
            failed.append(line.strip())
        elif "INCOMPLETE" in line:
            incomplete.append(line.strip())

    if failed:
        for entry in failed[:5]:
            results.append(CheckResult(CATEGORY, "ARP failure", ERROR,
                                       entry,
                                       "Host unreachable or MAC address unresolvable; check connectivity"))
    if incomplete:
        for entry in incomplete[:5]:
            results.append(CheckResult(CATEGORY, "ARP incomplete", WARN,
                                       entry,
                                       "ARP resolution in progress or timed out; may indicate intermittent connectivity"))
    if not failed and not incomplete:
        results.append(CheckResult(CATEGORY, "ARP table", OK, "No FAILED or INCOMPLETE ARP entries"))
    return results


def check_ring_buffers():
    results = []
    ifaces = _get_interfaces()
    for iface in ifaces:
        if not command_exists("ethtool"):
            break
        stdout, _, rc = run(f"ethtool -g {iface}", sudo=True)
        if rc != 0 or not stdout:
            continue

        sections = {}
        current = None
        for line in stdout.splitlines():
            if "Pre-set maximums" in line:
                current = "max"
                sections[current] = {}
            elif "Current hardware settings" in line:
                current = "current"
                sections[current] = {}
            elif current:
                m = re.match(r"\s*(RX|TX|RX Mini|RX Jumbo):\s*(\d+)", line)
                if m:
                    sections[current][m.group(1)] = int(m.group(2))

        if "max" in sections and "current" in sections:
            for key in ["RX", "TX"]:
                if key in sections["max"] and key in sections["current"]:
                    cur = sections["current"][key]
                    maximum = sections["max"][key]
                    if maximum > 0 and cur < maximum // 2:
                        results.append(CheckResult(CATEGORY, f"Ring buffer {key} ({iface})", WARN,
                                                   f"{key} ring: {cur}/{maximum} (current/max)",
                                                   f"Consider increasing: ethtool -G {iface} {key.lower()} {maximum}"))
                    else:
                        results.append(CheckResult(CATEGORY, f"Ring buffer {key} ({iface})", OK,
                                                   f"{key} ring: {cur}/{maximum}"))
    return results


def run_all():
    results = []
    results += check_driver_errors()
    results += check_crc_errors()
    results += check_tx_drops()
    results += check_duplex()
    results += check_lag_lacp()
    results += check_collisions()
    results += check_invalid_macs()
    results += check_arp_failures()
    results += check_ring_buffers()
    return results
