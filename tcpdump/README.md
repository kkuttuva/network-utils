# network-utils

A growing collection of utilities for massaging and preparing network packet captures (`.pcap`) before uploading to external tools or sharing with third parties.

---

## `pcap_tool.py` — PCAP Sanitizer

Reads a tcpdump/Wireshark `.pcap` file, applies one of the transformations below, and writes a clean output file.

### Requirements

```
pip install dpkt
```

### Usage

```
python3 pcap_tool.py <command> <input.pcap> [options]
```

---

### Commands

#### `anonymize` — Replace private IPs with random public IPs

Replaces all RFC-1918 source/destination addresses with stable, randomly-generated public IPs that don't appear anywhere else in the stream. Recalculates IP (and clears transport) checksums. Emits a mapping table so you can correlate original ↔ anonymized addresses.

```bash
# Basic: writes capture_anon.pcap + prints mapping table
python3 pcap_tool.py anonymize capture.pcap

# Save mapping to CSV as well
python3 pcap_tool.py anonymize capture.pcap --map-file mapping.csv

# Explicit output file
python3 pcap_tool.py anonymize capture.pcap -o sanitized.pcap --map-file map.csv

# Reproducible run (same seed → same replacement IPs)
python3 pcap_tool.py anonymize capture.pcap --seed 42

# Dry-run: show mapping without writing a file
python3 pcap_tool.py anonymize capture.pcap --dry-run
```

Example output:

```
[*] Input : capture.pcap
[*] Output: capture_anon.pcap
[+] Processed 1842 packets in 0.043s
[+] 3 unique private address(es) anonymized

+---------------+------------------+
| Private IP    | Anonymized IP    |
+---------------+------------------+
| 10.0.0.5      | 45.112.203.17    |
| 192.168.1.1   | 78.34.199.6      |
| 172.16.5.100  | 203.44.11.222    |
+---------------+------------------+

[+] Output size: 284,512 bytes  →  capture_anon.pcap
```

**Anonymization rules:**
- Only `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` addresses are rewritten
- Public addresses in the capture are left untouched
- The same private IP always maps to the same replacement IP within a run
- Replacement IPs exclude loopback, link-local, multicast, reserved, and documentation ranges
- IP header checksum is recomputed; TCP/UDP checksums are zeroed (marked invalid)

---

#### `truncate` — Snap packets to a fixed byte length

Truncates IP payloads so that no frame exceeds the snap-len. Useful for stripping application data while preserving full headers for flow/protocol analysis.

```bash
# Default snap-len = 64 bytes
python3 pcap_tool.py truncate capture.pcap

# Custom snap-len
python3 pcap_tool.py truncate capture.pcap -s 128

# Explicit output file
python3 pcap_tool.py truncate capture.pcap -o trimmed.pcap --snap-len 96

# Dry-run: report stats without writing
python3 pcap_tool.py truncate capture.pcap --dry-run
```

**Truncation rules:**
- Ethernet + IP headers are always preserved in full
- Only the IP payload (TCP/UDP/other) is truncated
- `ip.len` is updated to reflect the shorter payload
- IP header checksum is recomputed
- TCP/UDP transport checksum is zeroed (frame is intentionally partial)
- Packets already shorter than snap-len are passed through unchanged

---

### All options

```
pcap_tool.py anonymize [-h] [-o OUTPUT] [--map-file FILE] [--no-map]
                        [--seed SEED] [--dry-run] input

pcap_tool.py truncate  [-h] [-o OUTPUT] [-s BYTES] [--dry-run] input
```

---

### Running tests

```bash
python3 test_pcap_tool.py -v
```

29 tests covering: private/public classification, anonymization correctness, checksum validity, stable mapping, seed reproducibility, truncation sizing, IP length updates, end-to-end pcap read/write, CSV output, and dry-run mode.

---

### Roadmap / future ideas

- `combine` — merge multiple captures into one with relative timestamp normalization  
- IPv6 anonymization  
- Payload scrubbing (zero-fill or pattern-fill truncated bytes)  
- `--format json` mapping output  
- Progress bar for large captures  
