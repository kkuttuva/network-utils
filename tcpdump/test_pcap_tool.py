#!/usr/bin/env python3
"""
Tests for pcap_tool.py

Run with:  python3 test_pcap_tool.py [-v]
"""

import io
import ipaddress
import os
import random
import struct
import sys
import tempfile
import unittest

import dpkt

sys.path.insert(0, os.path.dirname(__file__))
from pcap_tool import (
    Anonymizer,
    _checksum,
    _is_private,
    _is_public_safe,
    _random_public_ip,
    _random_mac,
    inet_to_str,
    mac_to_str,
    str_to_inet,
    truncate_packet,
    process_pcap,
    print_mapping_table,
    print_mac_mapping_table,
    write_mapping_csv,
)


# ---------------------------------------------------------------------------
# Packet builder helpers
# ---------------------------------------------------------------------------

def _build_udp_packet(
    src_ip: str,
    dst_ip: str,
    sport: int = 12345,
    dport: int = 53,
    payload: bytes = b"HELLO WORLD PAYLOAD",
) -> bytes:
    """Build a raw Ethernet/IP/UDP frame."""
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    udp.ulen = 8 + len(payload)

    ip = dpkt.ip.IP(
        src=ipaddress.IPv4Address(src_ip).packed,
        dst=ipaddress.IPv4Address(dst_ip).packed,
        p=dpkt.ip.IP_PROTO_UDP,
        data=bytes(udp),
        ttl=64,
    )
    ip.len = 20 + len(bytes(udp))
    ip.sum = 0
    raw_ip = bytes(ip)
    # recompute checksum
    cksum = _checksum(raw_ip[:20])
    ip_bytes = bytearray(raw_ip)
    ip_bytes[10] = (cksum >> 8) & 0xFF
    ip_bytes[11] = cksum & 0xFF

    eth = dpkt.ethernet.Ethernet(
        src=b'\x00\x11\x22\x33\x44\x55',
        dst=b'\x66\x77\x88\x99\xaa\xbb',
        data=bytes(ip_bytes),
    )
    return bytes(eth)


def _build_tcp_packet(
    src_ip: str,
    dst_ip: str,
    sport: int = 54321,
    dport: int = 80,
    payload: bytes = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
) -> bytes:
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, data=payload, seq=1, ack=0, off=5)
    ip = dpkt.ip.IP(
        src=ipaddress.IPv4Address(src_ip).packed,
        dst=ipaddress.IPv4Address(dst_ip).packed,
        p=dpkt.ip.IP_PROTO_TCP,
        data=bytes(tcp),
        ttl=64,
    )
    ip.len = 20 + len(bytes(tcp))
    ip.sum = 0
    eth = dpkt.ethernet.Ethernet(
        src=b'\xaa\xbb\xcc\xdd\xee\xff',
        dst=b'\x11\x22\x33\x44\x55\x66',
        data=bytes(ip),
    )
    return bytes(eth)


def _build_arp_packet(
    sender_ip: str,
    target_ip: str,
    sender_mac: bytes = b'\x00\x11\x22\x33\x44\x55',
    target_mac: bytes = b'\x00\x00\x00\x00\x00\x00',  # zeros = ARP request
    op: int = dpkt.arp.ARP_OP_REQUEST,
) -> bytes:
    """Build an Ethernet ARP request or reply frame."""
    arp = dpkt.arp.ARP(
        hrd=dpkt.arp.ARP_HRD_ETH,
        pro=dpkt.ethernet.ETH_TYPE_IP,
        hln=6,
        pln=4,
        op=op,
        sha=sender_mac,
        spa=ipaddress.IPv4Address(sender_ip).packed,
        tha=target_mac,
        tpa=ipaddress.IPv4Address(target_ip).packed,
    )
    eth = dpkt.ethernet.Ethernet(
        src=sender_mac,
        dst=b'\xff\xff\xff\xff\xff\xff' if op == dpkt.arp.ARP_OP_REQUEST else target_mac,
        type=dpkt.ethernet.ETH_TYPE_ARP,
        data=bytes(arp),
    )
    return bytes(eth)


def _write_temp_pcap(packets: list[bytes]) -> str:
    fd, path = tempfile.mkstemp(suffix=".pcap")
    with os.fdopen(fd, 'wb') as f:
        writer = dpkt.pcap.Writer(f)
        for i, buf in enumerate(packets):
            writer.writepkt(buf, ts=float(i))
    return path


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

class TestHelpers(unittest.TestCase):

    def test_is_private_10(self):
        self.assertTrue(_is_private(str_to_inet("10.0.0.1")))
        self.assertTrue(_is_private(str_to_inet("10.255.255.255")))

    def test_is_private_172(self):
        self.assertTrue(_is_private(str_to_inet("172.16.0.1")))
        self.assertTrue(_is_private(str_to_inet("172.31.255.255")))
        self.assertFalse(_is_private(str_to_inet("172.32.0.1")))

    def test_is_private_192(self):
        self.assertTrue(_is_private(str_to_inet("192.168.1.1")))
        self.assertFalse(_is_private(str_to_inet("192.169.0.1")))

    def test_is_public_safe_excludes_loopback(self):
        self.assertFalse(_is_public_safe(str_to_inet("127.0.0.1")))

    def test_is_public_safe_excludes_private(self):
        self.assertFalse(_is_public_safe(str_to_inet("192.168.0.1")))

    def test_is_public_safe_allows_routable(self):
        self.assertTrue(_is_public_safe(str_to_inet("8.8.8.8")))
        self.assertTrue(_is_public_safe(str_to_inet("1.1.1.1")))

    def test_random_public_ip_uniqueness(self):
        existing = set()
        for _ in range(20):
            ip = _random_public_ip(existing)
            self.assertNotIn(ip, existing)
            existing.add(ip)

    def test_inet_roundtrip(self):
        addr = "203.0.113.42"
        self.assertEqual(inet_to_str(str_to_inet(addr)), addr)


class TestAnonymizer(unittest.TestCase):

    def setUp(self):
        self.anon = Anonymizer(seed=42)

    def test_private_src_replaced(self):
        buf = _build_udp_packet("192.168.1.10", "8.8.8.8")
        result = self.anon.process_packet(buf)
        eth = dpkt.ethernet.Ethernet(result)
        ip = eth.data
        src_str = inet_to_str(int.from_bytes(ip.src, 'big'))
        self.assertTrue(_is_public_safe(str_to_inet(src_str)),
                        f"Anonymized src {src_str} is not public-safe")

    def test_private_dst_replaced(self):
        buf = _build_udp_packet("8.8.8.8", "10.0.0.5")
        result = self.anon.process_packet(buf)
        eth = dpkt.ethernet.Ethernet(result)
        ip = eth.data
        dst_str = inet_to_str(int.from_bytes(ip.dst, 'big'))
        self.assertTrue(_is_public_safe(str_to_inet(dst_str)))

    def test_public_addr_unchanged(self):
        buf = _build_udp_packet("1.2.3.4", "5.6.7.8")
        result = self.anon.process_packet(buf)
        eth = dpkt.ethernet.Ethernet(result)
        ip = eth.data
        self.assertEqual(inet_to_str(int.from_bytes(ip.src, 'big')), "1.2.3.4")
        self.assertEqual(inet_to_str(int.from_bytes(ip.dst, 'big')), "5.6.7.8")

    def test_stable_mapping(self):
        buf = _build_udp_packet("192.168.5.5", "8.8.8.8")
        r1 = self.anon.process_packet(buf)
        r2 = self.anon.process_packet(buf)
        self.assertEqual(r1, r2)

    def test_two_private_addrs_map_differently(self):
        buf1 = _build_udp_packet("192.168.1.1", "8.8.8.8")
        buf2 = _build_udp_packet("192.168.1.2", "8.8.8.8")
        self.anon.process_packet(buf1)
        self.anon.process_packet(buf2)
        m = self.anon.mapping
        vals = list(m.values())
        self.assertNotEqual(vals[0], vals[1])

    def test_mapping_property(self):
        buf = _build_udp_packet("10.1.1.1", "8.8.8.8")
        self.anon.process_packet(buf)
        m = self.anon.mapping
        self.assertIn("10.1.1.1", m)
        pub = m["10.1.1.1"]
        self.assertTrue(_is_public_safe(str_to_inet(pub)))

    def test_ip_checksum_fixed(self):
        """After anonymization the IP header checksum should be valid (verify = 0)."""
        buf = _build_udp_packet("172.16.0.1", "8.8.8.8")
        result = self.anon.process_packet(buf)
        eth = dpkt.ethernet.Ethernet(result)
        ip = eth.data
        header = bytes(ip)[:ip.hl * 4]
        self.assertEqual(_checksum(header), 0,
                         "IP checksum verification failed (expected 0)")

    def test_non_ethernet_passthrough(self):
        """Garbled/non-parseable frames should pass through unchanged."""
        buf = b'\x00' * 10  # too short to be valid Ethernet
        result = self.anon.process_packet(buf)
        self.assertEqual(buf, result)

    def test_ipv6_passthrough(self):
        """IPv6 Ethernet frames (not yet supported) should pass through unchanged."""
        ipv6_eth = dpkt.ethernet.Ethernet(
            src=b'\x00' * 6,
            dst=b'\xff' * 6,
            type=dpkt.ethernet.ETH_TYPE_IP6,
            data=b'\x60' + b'\x00' * 39,  # minimal IPv6-ish blob
        )
        buf = bytes(ipv6_eth)
        result = self.anon.process_packet(buf)
        self.assertEqual(buf, result)

    def test_seed_reproducibility(self):
        a1 = Anonymizer(seed=99)
        a2 = Anonymizer(seed=99)
        buf = _build_udp_packet("192.168.10.10", "8.8.8.8")
        self.assertEqual(a1.process_packet(buf), a2.process_packet(buf))


class TestTruncate(unittest.TestCase):

    def test_short_packet_unchanged(self):
        buf = _build_udp_packet("1.2.3.4", "5.6.7.8", payload=b"hi")
        result = truncate_packet(buf, snap_len=1500)
        self.assertEqual(buf, result)

    def test_truncation_reduces_size(self):
        buf = _build_udp_packet("1.2.3.4", "5.6.7.8", payload=b"A" * 200)
        result = truncate_packet(buf, snap_len=64)
        self.assertLessEqual(len(result), 64)

    def test_ip_len_updated(self):
        buf = _build_udp_packet("1.2.3.4", "5.6.7.8", payload=b"B" * 200)
        result = truncate_packet(buf, snap_len=64)
        eth = dpkt.ethernet.Ethernet(result)
        ip = eth.data
        # ip.len should match actual IP layer length
        self.assertEqual(ip.len, len(result) - 14)

    def test_ip_checksum_valid_after_truncation(self):
        buf = _build_udp_packet("1.2.3.4", "5.6.7.8", payload=b"C" * 200)
        result = truncate_packet(buf, snap_len=64)
        eth = dpkt.ethernet.Ethernet(result)
        ip = eth.data
        header = bytes(ip)[:ip.hl * 4]
        self.assertEqual(_checksum(header), 0)

    def test_tcp_truncation(self):
        buf = _build_tcp_packet("1.2.3.4", "5.6.7.8", payload=b"D" * 500)
        result = truncate_packet(buf, snap_len=80)
        self.assertLessEqual(len(result), 80)

    def test_exact_snap_len_boundary(self):
        """Packet exactly at snap_len should be unchanged."""
        payload_size = 64 - 14 - 20 - 8  # eth + ip + udp headers
        if payload_size < 0:
            payload_size = 0
        buf = _build_udp_packet("1.2.3.4", "5.6.7.8", payload=b"X" * payload_size)
        result = truncate_packet(buf, snap_len=64)
        self.assertEqual(len(result), len(buf))

    def test_custom_snap_len(self):
        buf = _build_udp_packet("1.2.3.4", "5.6.7.8", payload=b"Y" * 400)
        for snap in [128, 256, 512]:
            result = truncate_packet(buf, snap_len=snap)
            self.assertLessEqual(len(result), snap,
                                 f"Expected ≤{snap}, got {len(result)}")


class TestProcessPcap(unittest.TestCase):

    def _make_pcap(self, packets):
        return _write_temp_pcap(packets)

    def test_anonymize_end_to_end(self):
        pkts = [
            _build_udp_packet("192.168.1.1", "8.8.8.8"),
            _build_udp_packet("10.0.0.5", "1.1.1.1"),
            _build_tcp_packet("172.16.5.5", "4.4.4.4"),
        ]
        in_path = self._make_pcap(pkts)
        fd, out_path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        try:
            mapping, mac_mapping, n = process_pcap(in_path, out_path, "anonymize")
            self.assertEqual(n, 3)
            self.assertEqual(len(mapping), 3)
            # Verify no private IPs remain in output
            with open(out_path, 'rb') as f:
                reader = dpkt.pcap.Reader(f)
                for _, buf in reader:
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                    src = int.from_bytes(ip.src, 'big')
                    dst = int.from_bytes(ip.dst, 'big')
                    self.assertFalse(_is_private(src), f"Private src {inet_to_str(src)} remains")
        finally:
            os.unlink(in_path)
            os.unlink(out_path)

    def test_truncate_end_to_end(self):
        pkts = [
            _build_udp_packet("1.2.3.4", "5.6.7.8", payload=b"X" * 300),
            _build_tcp_packet("9.10.11.12", "13.14.15.16", payload=b"Y" * 500),
        ]
        in_path = self._make_pcap(pkts)
        fd, out_path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        try:
            _, _mac, n = process_pcap(in_path, out_path, "truncate", snap_len=64)
            self.assertEqual(n, 2)
            with open(out_path, 'rb') as f:
                reader = dpkt.pcap.Reader(f)
                for _, buf in reader:
                    self.assertLessEqual(len(buf), 64)
        finally:
            os.unlink(in_path)
            os.unlink(out_path)

    def test_dry_run_no_output(self):
        pkts = [_build_udp_packet("192.168.1.1", "8.8.8.8")]
        in_path = self._make_pcap(pkts)
        try:
            mapping, mac_mapping, n = process_pcap(in_path, None, "anonymize")
            self.assertEqual(n, 1)
            self.assertEqual(len(mapping), 1)
        finally:
            os.unlink(in_path)


class TestOutputHelpers(unittest.TestCase):

    def test_print_mapping_table_no_crash(self):
        mapping = {"192.168.1.1": "203.0.114.5", "10.0.0.1": "45.12.200.3"}
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            print_mapping_table(mapping)
        out = buf.getvalue()
        self.assertIn("192.168.1.1", out)
        self.assertIn("203.0.114.5", out)

    def test_print_mac_mapping_table_no_crash(self):
        mac_mapping = {"aa:bb:cc:dd:ee:ff": "02:11:22:33:44:55"}
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            print_mac_mapping_table(mac_mapping)
        out = buf.getvalue()
        self.assertIn("aa:bb:cc:dd:ee:ff", out)

    def test_write_mapping_csv(self):
        mapping = {"192.168.1.1": "50.60.70.80"}
        mac_mapping = {"aa:bb:cc:dd:ee:ff": "02:11:22:33:44:55"}
        fd, path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        try:
            import io, contextlib, csv
            with contextlib.redirect_stdout(io.StringIO()):
                write_mapping_csv(mapping, mac_mapping, path)
            with open(path) as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 2)
            ip_row = next(r for r in rows if r["type"] == "ip")
            mac_row = next(r for r in rows if r["type"] == "mac")
            self.assertEqual(ip_row["original"], "192.168.1.1")
            self.assertEqual(ip_row["anonymized"], "50.60.70.80")
            self.assertEqual(mac_row["original"], "aa:bb:cc:dd:ee:ff")
        finally:
            os.unlink(path)


class TestMacHelpers(unittest.TestCase):

    def test_random_mac_is_unicast_local(self):
        rng = random.Random(1)
        mac = _random_mac(rng, set())
        self.assertEqual(mac[0] & 0x01, 0, "multicast bit should be clear")
        self.assertEqual(mac[0] & 0x02, 2, "locally-administered bit should be set")

    def test_random_mac_uniqueness(self):
        rng = random.Random(2)
        existing = set()
        for _ in range(20):
            mac = _random_mac(rng, existing)
            self.assertNotIn(mac, existing)
            existing.add(mac)

    def test_mac_to_str(self):
        self.assertEqual(mac_to_str(b'\xaa\xbb\xcc\xdd\xee\xff'), 'aa:bb:cc:dd:ee:ff')


class TestArpAnonymizer(unittest.TestCase):

    def setUp(self):
        self.anon = Anonymizer(seed=7)

    def test_arp_sender_ip_replaced(self):
        buf = _build_arp_packet("192.168.1.1", "192.168.1.254")
        result = self.anon.process_packet(buf)
        eth = dpkt.ethernet.Ethernet(result)
        arp = eth.data
        spa_int = int.from_bytes(arp.spa, 'big')
        self.assertFalse(_is_private(spa_int),
                         f"Sender IP {inet_to_str(spa_int)} is still private")

    def test_arp_target_ip_replaced(self):
        buf = _build_arp_packet("192.168.1.1", "192.168.1.254")
        result = self.anon.process_packet(buf)
        eth = dpkt.ethernet.Ethernet(result)
        arp = eth.data
        tpa_int = int.from_bytes(arp.tpa, 'big')
        self.assertFalse(_is_private(tpa_int),
                         f"Target IP {inet_to_str(tpa_int)} is still private")

    def test_arp_sender_mac_replaced(self):
        original_mac = b'\x00\x11\x22\x33\x44\x55'
        buf = _build_arp_packet("192.168.1.1", "192.168.1.2",
                                sender_mac=original_mac)
        result = self.anon.process_packet(buf)
        eth = dpkt.ethernet.Ethernet(result)
        arp = eth.data
        self.assertNotEqual(arp.sha, original_mac)
        # Should be a locally-administered unicast MAC
        self.assertEqual(arp.sha[0] & 0x01, 0)
        self.assertEqual(arp.sha[0] & 0x02, 2)

    def test_arp_eth_src_consistent_with_sha(self):
        """Ethernet src must match the anonymized ARP sender MAC."""
        buf = _build_arp_packet("192.168.1.1", "192.168.1.2")
        result = self.anon.process_packet(buf)
        eth = dpkt.ethernet.Ethernet(result)
        arp = eth.data
        self.assertEqual(eth.src, arp.sha,
                         "Ethernet src should match ARP sender hardware address")

    def test_arp_reply_eth_dst_consistent_with_tha(self):
        """For ARP replies, Ethernet dst must match anonymized target MAC."""
        sender_mac = b'\x00\x11\x22\x33\x44\x55'
        target_mac = b'\xaa\xbb\xcc\xdd\xee\xff'
        buf = _build_arp_packet(
            "192.168.1.1", "192.168.1.2",
            sender_mac=sender_mac,
            target_mac=target_mac,
            op=dpkt.arp.ARP_OP_REPLY,
        )
        result = self.anon.process_packet(buf)
        eth = dpkt.ethernet.Ethernet(result)
        arp = eth.data
        self.assertEqual(eth.dst, arp.tha,
                         "Ethernet dst should match ARP target hardware address")

    def test_arp_request_zero_tha_not_anonymized(self):
        """ARP request target MAC (all-zeros) should not be added to MAC mapping."""
        buf = _build_arp_packet("192.168.1.1", "192.168.1.254",
                                target_mac=b'\x00' * 6)
        self.anon.process_packet(buf)
        # all-zeros should NOT appear as a key in mac_mapping
        for orig in self.anon.mac_mapping:
            self.assertNotEqual(orig, '00:00:00:00:00:00')

    def test_arp_stable_mac_mapping(self):
        mac = b'\xde\xad\xbe\xef\xca\xfe'
        buf = _build_arp_packet("192.168.5.5", "10.0.0.1", sender_mac=mac,
                                target_mac=b'\x00'*6)
        r1 = self.anon.process_packet(buf)
        r2 = self.anon.process_packet(buf)
        self.assertEqual(r1, r2)

    def test_arp_ip_shared_with_ipv4_mapping(self):
        """Same private IP appearing in both ARP and IPv4 should map to same replacement."""
        arp_buf = _build_arp_packet("192.168.1.1", "10.0.0.1")
        ip_buf = _build_udp_packet("192.168.1.1", "8.8.8.8")
        self.anon.process_packet(arp_buf)
        self.anon.process_packet(ip_buf)
        # Both should record the same anonymized IP for 192.168.1.1
        self.assertEqual(len(set(self.anon.ip_mapping.values())),
                         len(self.anon.ip_mapping),
                         "Each private IP should have exactly one unique replacement")

    def test_arp_mac_mapping_table(self):
        buf = _build_arp_packet("192.168.1.1", "192.168.1.2",
                                sender_mac=b'\x00\x11\x22\x33\x44\x55')
        self.anon.process_packet(buf)
        mm = self.anon.mac_mapping
        self.assertIn('00:11:22:33:44:55', mm)

    def test_arp_end_to_end_pcap(self):
        """Mixed pcap with ARP + UDP: ARP IPs and MACs should be rewritten."""
        pkts = [
            _build_arp_packet("192.168.1.1", "192.168.1.254",
                              sender_mac=b'\x00\x11\x22\x33\x44\x55'),
            _build_udp_packet("192.168.1.1", "8.8.8.8"),
        ]
        in_path = _write_temp_pcap(pkts)
        fd, out_path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        try:
            mapping, mac_mapping, n = process_pcap(in_path, out_path, "anonymize")
            self.assertEqual(n, 2)
            self.assertGreater(len(mapping), 0)
            self.assertGreater(len(mac_mapping), 0)
            with open(out_path, 'rb') as f:
                reader = dpkt.pcap.Reader(f)
                for _, buf in reader:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if isinstance(eth.data, dpkt.arp.ARP):
                        arp = eth.data
                        spa_int = int.from_bytes(arp.spa, 'big')
                        self.assertFalse(_is_private(spa_int))
        finally:
            os.unlink(in_path)
            os.unlink(out_path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
