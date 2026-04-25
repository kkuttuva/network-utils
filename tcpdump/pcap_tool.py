#!/usr/bin/env python3
"""
pcap_tool.py — PCAP massage utility for tcpdump captures.

Supported operations:
  anonymize   Translate private IPv4 addresses to random public IPs,
              and emit a mapping table (CSV or pretty-print).
  truncate    Truncate every packet payload to N bytes (default 64).

Usage examples:
  pcap_tool.py anonymize  capture.pcap -o anon.pcap --map-file map.csv
  pcap_tool.py truncate   capture.pcap -o trunc.pcap --snap-len 128
  pcap_tool.py anonymize  capture.pcap --map-file map.csv   # stdout passthrough
"""

import argparse
import csv
import ipaddress
import os
import random
import struct
import sys
import time
from pathlib import Path

import dpkt


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RFC_1918_NETWORKS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]

# Public ranges we draw replacement IPs from (exclude well-known reserved blocks)
# We stay within 1.0.0.0 – 223.255.255.255 and avoid RFC-1918 / loopback / link-local
_PUBLIC_EXCLUDE = [
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("100.64.0.0/10"),   # shared address space
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.0.0.0/24"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("198.18.0.0/15"),
    ipaddress.IPv4Network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.IPv4Network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.IPv4Network("224.0.0.0/4"),      # multicast
    ipaddress.IPv4Network("240.0.0.0/4"),      # reserved
    ipaddress.IPv4Network("255.255.255.255/32"),
]


def _is_private(addr_int: int) -> bool:
    addr = ipaddress.IPv4Address(addr_int)
    return any(addr in net for net in RFC_1918_NETWORKS)


def _is_public_safe(addr_int: int) -> bool:
    addr = ipaddress.IPv4Address(addr_int)
    return not any(addr in net for net in _PUBLIC_EXCLUDE)


def _random_public_ip(existing: set, rng: random.Random | None = None) -> int:
    """Generate a random public IPv4 address not already in *existing*."""
    _rng = rng or random
    for _ in range(100_000):
        a = _rng.randint(1, 223)
        b = _rng.randint(0, 255)
        c = _rng.randint(0, 255)
        d = _rng.randint(1, 254)
        candidate = (a << 24) | (b << 16) | (c << 8) | d
        if _is_public_safe(candidate) and candidate not in existing:
            return candidate
    raise RuntimeError("Could not find a unique public IP after 100k attempts")


def inet_to_str(addr_int: int) -> str:
    return str(ipaddress.IPv4Address(addr_int))


def str_to_inet(addr_str: str) -> int:
    return int(ipaddress.IPv4Address(addr_str))


def mac_to_str(mac: bytes) -> str:
    return ':'.join(f'{b:02x}' for b in mac)


def _random_mac(rng: random.Random, existing: set) -> bytes:
    """Generate a random unicast, locally-administered MAC not in *existing*."""
    for _ in range(100_000):
        b = bytearray(rng.randbytes(6))
        b[0] = (b[0] & 0xFC) | 0x02  # clear multicast bit, set locally-administered
        mac = bytes(b)
        if mac not in existing:
            return mac
    raise RuntimeError("Could not find a unique MAC after 100k attempts")


# ---------------------------------------------------------------------------
# IP checksum
# ---------------------------------------------------------------------------

def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def _fix_ip_checksum(ip: dpkt.ip.IP) -> None:
    ip.sum = 0
    ip.sum = _checksum(bytes(ip)[:ip.hl * 4])


def _fix_transport_checksum(ip: dpkt.ip.IP) -> None:
    """Recompute TCP/UDP checksum using pseudo-header."""
    proto = ip.p
    if proto not in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):
        return

    transport = ip.data
    transport.sum = 0
    segment = bytes(transport)

    # pseudo-header: src, dst, zero, proto, segment length
    pseudo = struct.pack('!4s4sBBH',
                         ip.src, ip.dst, 0, proto, len(segment))
    transport.sum = _checksum(pseudo + segment)


# ---------------------------------------------------------------------------
# Core operations
# ---------------------------------------------------------------------------

class Anonymizer:
    """
    Map private IPv4 addresses → stable random public IPv4 addresses.
    Map real MAC addresses → stable random locally-administered MACs.

    ARP packets get both their IP fields and hardware-address fields rewritten.
    The Ethernet src/dst is kept consistent with the inner ARP sender/target MACs.
    """

    def __init__(self, seed: int | None = None):
        self._rng = random.Random(seed)  # isolated RNG; seed=None → random
        self._ip_map: dict[int, int] = {}    # private_int → public_int
        self._used_public: set = set()
        self._mac_map: dict[bytes, bytes] = {}  # original_mac → anon_mac
        self._used_macs: set = set()

    # ------------------------------------------------------------------ IP --

    def translate_ip(self, addr_int: int) -> int:
        """Return the public replacement for a private address (create if new)."""
        if addr_int not in self._ip_map:
            pub = _random_public_ip(self._used_public, self._rng)
            self._ip_map[addr_int] = pub
            self._used_public.add(pub)
        return self._ip_map[addr_int]

    # ----------------------------------------------------------------- MAC --

    def translate_mac(self, mac: bytes) -> bytes:
        """Return a stable random MAC replacement for *mac* (create if new)."""
        if mac not in self._mac_map:
            new_mac = _random_mac(self._rng, self._used_macs)
            self._mac_map[mac] = new_mac
            self._used_macs.add(new_mac)
        return self._mac_map[mac]

    # ------------------------------------------------------------ packets --

    def _process_ipv4(self, eth: dpkt.ethernet.Ethernet) -> bytes:
        """Rewrite private src/dst IPs in an IPv4 frame; fix checksums."""
        ip = eth.data
        src_int = int.from_bytes(ip.src, 'big')
        dst_int = int.from_bytes(ip.dst, 'big')

        changed = False
        if _is_private(src_int):
            ip.src = self.translate_ip(src_int).to_bytes(4, 'big')
            changed = True
        if _is_private(dst_int):
            ip.dst = self.translate_ip(dst_int).to_bytes(4, 'big')
            changed = True

        if changed:
            _fix_ip_checksum(ip)
            _fix_transport_checksum(ip)
            return bytes(eth)
        return bytes(eth)

    def _process_arp(self, eth: dpkt.ethernet.Ethernet) -> bytes:
        """
        Rewrite ARP sender/target IPs and hardware addresses.
        Also update the Ethernet src/dst to match the rewritten MACs.
        """
        arp = eth.data
        if not isinstance(arp, dpkt.arp.ARP):
            return bytes(eth)

        # Only handle IPv4-over-Ethernet ARP (hrd=1, pro=0x0800)
        if arp.hrd != dpkt.arp.ARP_HRD_ETH or arp.pro != dpkt.ethernet.ETH_TYPE_IP:
            return bytes(eth)

        changed = False

        # --- sender hardware address (sha) ---
        if len(arp.sha) == 6:
            new_sha = self.translate_mac(arp.sha)
            if new_sha != arp.sha:
                arp.sha = new_sha
                eth.src = new_sha          # keep Ethernet src consistent
                changed = True

        # --- sender protocol address (spa) — IPv4 ---
        if len(arp.spa) == 4:
            spa_int = int.from_bytes(arp.spa, 'big')
            if _is_private(spa_int):
                arp.spa = self.translate_ip(spa_int).to_bytes(4, 'big')
                changed = True

        # --- target hardware address (tha) ---
        # For ARP requests tha is all-zeros (broadcast placeholder); anonymize
        # only if it looks like a real unicast address.
        if len(arp.tha) == 6 and arp.tha not in (b'\x00'*6, b'\xff'*6):
            new_tha = self.translate_mac(arp.tha)
            if new_tha != arp.tha:
                arp.tha = new_tha
                eth.dst = new_tha          # keep Ethernet dst consistent
                changed = True

        # --- target protocol address (tpa) — IPv4 ---
        if len(arp.tpa) == 4:
            tpa_int = int.from_bytes(arp.tpa, 'big')
            if _is_private(tpa_int):
                arp.tpa = self.translate_ip(tpa_int).to_bytes(4, 'big')
                changed = True

        if changed:
            return bytes(eth)
        return bytes(eth)

    def process_packet(self, buf: bytes) -> bytes:
        """Dispatch to the right handler based on Ethernet type."""
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except Exception:
            return buf

        if isinstance(eth.data, dpkt.ip.IP):
            return self._process_ipv4(eth)
        if isinstance(eth.data, dpkt.arp.ARP):
            return self._process_arp(eth)
        return buf  # other types pass through unchanged

    # ---------------------------------------------------------- mappings --

    @property
    def ip_mapping(self) -> dict[str, str]:
        """Human-readable {private_ip: anonymized_ip} mapping."""
        return {inet_to_str(k): inet_to_str(v) for k, v in self._ip_map.items()}

    @property
    def mac_mapping(self) -> dict[str, str]:
        """Human-readable {original_mac: anonymized_mac} mapping."""
        return {mac_to_str(k): mac_to_str(v) for k, v in self._mac_map.items()}

    @property
    def mapping(self) -> dict[str, str]:
        """Legacy alias — returns IP mapping (used by existing callers)."""
        return self.ip_mapping


def truncate_packet(buf: bytes, snap_len: int) -> bytes:
    """
    Truncate an Ethernet/IP packet so the IP payload is at most
    (snap_len - Ethernet_hdr - IP_hdr) bytes.  Fixes IP total-length
    and checksum; clears TCP/UDP checksum (set to 0 = disabled).
    """
    ETH_HDR = 14  # standard Ethernet II header

    if len(buf) <= snap_len:
        return buf

    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except Exception:
        return buf[:snap_len]

    if not isinstance(eth.data, dpkt.ip.IP):
        return buf[:snap_len]

    ip = eth.data
    ip_hdr_len = ip.hl * 4
    max_ip_payload = snap_len - ETH_HDR - ip_hdr_len

    if max_ip_payload <= 0:
        # snap_len too small to even hold headers; truncate raw
        return buf[:snap_len]

    # Truncate the IP payload
    original_payload = bytes(ip.data)
    if len(original_payload) <= max_ip_payload:
        return buf  # already fits

    truncated_payload = original_payload[:max_ip_payload]

    # Rebuild: set raw data so dpkt doesn't re-parse transport
    ip.data = truncated_payload
    ip.len = ip_hdr_len + len(truncated_payload)

    # Zero out transport checksum (now invalid) if TCP/UDP
    proto = ip.p
    if proto == dpkt.ip.IP_PROTO_TCP and len(truncated_payload) >= 18:
        # TCP checksum is at offset 16–17 within the TCP header
        tp = bytearray(truncated_payload)
        tp[16] = 0
        tp[17] = 0
        ip.data = bytes(tp)
    elif proto == dpkt.ip.IP_PROTO_UDP and len(truncated_payload) >= 8:
        tp = bytearray(truncated_payload)
        tp[6] = 0
        tp[7] = 0
        ip.data = bytes(tp)

    _fix_ip_checksum(ip)
    return bytes(eth)


# ---------------------------------------------------------------------------
# PCAP I/O
# ---------------------------------------------------------------------------

def process_pcap(
    input_path: str,
    output_path: str | None,
    operation: str,
    snap_len: int = 64,
    seed: int | None = None,
) -> dict[str, str]:
    """
    Read *input_path*, apply *operation*, write *output_path*.

    Returns the anonymization mapping dict (empty for truncate).
    """
    anonymizer = Anonymizer(seed=seed) if operation == "anonymize" else None

    with open(input_path, 'rb') as f:
        pcap_reader = dpkt.pcap.Reader(f)
        link_type = pcap_reader.datalink()

        # Collect all processed packets first so we can report stats
        packets: list[tuple[float, bytes]] = []
        for ts, buf in pcap_reader:
            if operation == "anonymize":
                buf = anonymizer.process_packet(buf)
            elif operation == "truncate":
                buf = truncate_packet(buf, snap_len)
            packets.append((ts, buf))

    if output_path:
        out_path = Path(output_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, 'wb') as f:
            writer = dpkt.pcap.Writer(f, linktype=link_type)
            for ts, buf in packets:
                writer.writepkt(buf, ts=ts)

    mapping = anonymizer.ip_mapping if anonymizer else {}
    mac_mapping = anonymizer.mac_mapping if anonymizer else {}
    return mapping, mac_mapping, len(packets)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def print_mapping_table(mapping: dict[str, str]) -> None:
    if not mapping:
        print("(no private addresses found)")
        return
    col = max(len(k) for k in mapping)
    sep = "+" + "-" * (col + 2) + "+" + "-" * 18 + "+"
    hdr = f"| {'Private IP':<{col}} | {'Anonymized IP':<16} |"
    print(sep)
    print(hdr)
    print(sep)
    for priv, pub in sorted(mapping.items()):
        print(f"| {priv:<{col}} | {pub:<16} |")
    print(sep)


def print_mac_mapping_table(mac_mapping: dict[str, str]) -> None:
    if not mac_mapping:
        return
    sep = "+" + "-" * 19 + "+" + "-" * 19 + "+"
    hdr = f"| {'Original MAC':<17} | {'Anonymized MAC':<17} |"
    print(sep)
    print(hdr)
    print(sep)
    for orig, anon in sorted(mac_mapping.items()):
        print(f"| {orig:<17} | {anon:<17} |")
    print(sep)


def write_mapping_csv(mapping: dict[str, str], mac_mapping: dict[str, str], path: str) -> None:
    with open(path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["type", "original", "anonymized"])
        for priv, pub in sorted(mapping.items()):
            writer.writerow(["ip", priv, pub])
        for orig, anon in sorted(mac_mapping.items()):
            writer.writerow(["mac", orig, anon])
    print(f"[+] Mapping written to: {path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pcap_tool",
        description="Massage pcap files before uploading or external processing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ---- anonymize ----
    anon = sub.add_parser(
        "anonymize",
        help="Replace private IPv4 addresses with random public IPs",
    )
    anon.add_argument("input", help="Input .pcap file")
    anon.add_argument("-o", "--output", help="Output .pcap file (default: <input>_anon.pcap)")
    anon.add_argument(
        "--map-file",
        metavar="FILE",
        help="Write CSV mapping table to FILE (e.g. mapping.csv)",
    )
    anon.add_argument(
        "--no-map",
        action="store_true",
        help="Suppress the console mapping table",
    )
    anon.add_argument(
        "--seed",
        type=int,
        default=None,
        help="RNG seed for reproducible anonymization",
    )
    anon.add_argument(
        "--dry-run",
        action="store_true",
        help="Show mapping without writing output pcap",
    )

    # ---- truncate ----
    trunc = sub.add_parser(
        "truncate",
        help="Truncate each packet to a fixed size (default 64 bytes)",
    )
    trunc.add_argument("input", help="Input .pcap file")
    trunc.add_argument("-o", "--output", help="Output .pcap file (default: <input>_trunc.pcap)")
    trunc.add_argument(
        "-s", "--snap-len",
        type=int,
        default=64,
        metavar="BYTES",
        help="Maximum packet size in bytes (default: 64)",
    )
    trunc.add_argument(
        "--dry-run",
        action="store_true",
        help="Report stats without writing output pcap",
    )

    return parser


def default_output(input_path: str, suffix: str) -> str:
    p = Path(input_path)
    return str(p.with_stem(p.stem + suffix))


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"[!] Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    out_file: str | None
    if args.dry_run:
        out_file = None
        print("[*] Dry-run mode — no output file will be written.")
    elif args.output:
        out_file = args.output
    elif args.command == "anonymize":
        out_file = default_output(args.input, "_anon")
    else:
        out_file = default_output(args.input, "_trunc")

    print(f"[*] Input : {args.input}")
    if out_file:
        print(f"[*] Output: {out_file}")

    # ---- Run ----
    t0 = time.perf_counter()

    if args.command == "anonymize":
        mapping, mac_mapping, n_pkts = process_pcap(
            args.input,
            out_file,
            operation="anonymize",
            seed=args.seed,
        )
        elapsed = time.perf_counter() - t0
        print(f"[+] Processed {n_pkts} packets in {elapsed:.3f}s")
        print(f"[+] {len(mapping)} unique private IP(s) anonymized, "
              f"{len(mac_mapping)} unique MAC(s) anonymized")

        if not args.no_map:
            if mapping:
                print("\nIP address mapping:")
                print_mapping_table(mapping)
            if mac_mapping:
                print("\nMAC address mapping:")
                print_mac_mapping_table(mac_mapping)
            print()

        if args.map_file:
            write_mapping_csv(mapping, mac_mapping, args.map_file)

    elif args.command == "truncate":
        _, _mac, n_pkts = process_pcap(
            args.input,
            out_file,
            operation="truncate",
            snap_len=args.snap_len,
        )
        elapsed = time.perf_counter() - t0
        print(f"[+] Processed {n_pkts} packets in {elapsed:.3f}s  "
              f"(snap-len={args.snap_len} bytes)")

    if out_file:
        size = os.path.getsize(out_file)
        print(f"[+] Output size: {size:,} bytes  →  {out_file}")


if __name__ == "__main__":
    main()
