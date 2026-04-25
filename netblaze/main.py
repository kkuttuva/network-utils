#!/usr/bin/env python3
"""
netblaze — Linux Network Troubleshooting Tool
Usage: python3 main.py [--only cat1,cat2] [--skip cat1,cat2] [--no-sudo] [--out DIR]
"""
import sys
import os
import argparse
import platform
import re

# Ensure checks/ and root are importable regardless of CWD
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from runner import check_sudo
from reporter import build_report, write_report, print_live_status, SEPARATOR_WIDE

# Ordered list of (display_name, module_name)
ALL_CATEGORIES = [
    ("Ethernet",    "checks.ethernet"),
    ("Interfaces",  "checks.interfaces"),
    ("IP Config",   "checks.ip_config"),
    ("TCP/UDP",     "checks.tcp_udp"),
    ("Application", "checks.application"),
    ("Firewall",    "checks.firewall"),
    ("Resources",   "checks.resources"),
    ("Sockstat",    "checks.sockstat"),
    ("NTP",         "checks.ntp"),
    ("DNS",         "checks.dns"),
    ("DHCP",        "checks.dhcp"),
]


def get_system_info():
    hostname = platform.node() or "unknown"
    kernel = platform.release() or "unknown"

    distro = "Linux"
    for path in ["/etc/os-release", "/etc/lsb-release"]:
        try:
            with open(path) as f:
                content = f.read()
            m = re.search(r'^PRETTY_NAME="?([^"\n]+)"?', content, re.MULTILINE)
            if m:
                distro = m.group(1)
                break
        except Exception:
            pass

    return hostname, kernel, distro


def parse_args():
    parser = argparse.ArgumentParser(
        description="netblaze: Linux Network Troubleshooting Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Categories:
  ethernet, interfaces, ip_config, tcp_udp, application,
  firewall, resources, sockstat, ntp, dns, dhcp

Examples:
  python3 main.py
  python3 main.py --only dns,ntp
  python3 main.py --skip firewall --out /tmp/reports
  python3 main.py --no-sudo
        """
    )
    parser.add_argument("--only", metavar="CAT,...",
                        help="Run only these categories (comma-separated)")
    parser.add_argument("--skip", metavar="CAT,...",
                        help="Skip these categories (comma-separated)")
    parser.add_argument("--no-sudo", action="store_true",
                        help="Never attempt sudo; skip all privileged checks")
    parser.add_argument("--out", metavar="DIR",
                        help="Directory to write the report file (default: current dir)")
    return parser.parse_args()


def filter_categories(args):
    cats = list(ALL_CATEGORIES)

    if args.only:
        only_set = {c.strip().lower().replace("-", "_").replace(" ", "_")
                    for c in args.only.split(",")}
        cats = [(name, mod) for name, mod in cats
                if name.lower().replace(" ", "_").replace("/", "_") in only_set
                or mod.split(".")[-1] in only_set]

    if args.skip:
        skip_set = {c.strip().lower().replace("-", "_").replace(" ", "_")
                    for c in args.skip.split(",")}
        cats = [(name, mod) for name, mod in cats
                if name.lower().replace(" ", "_").replace("/", "_") not in skip_set
                and mod.split(".")[-1] not in skip_set]

    return cats


def banner():
    print()
    print(SEPARATOR_WIDE)
    print("  NETBLAZE — Linux Network Troubleshooting Tool")
    print(SEPARATOR_WIDE)


def main():
    args = parse_args()
    banner()

    hostname, kernel, distro = get_system_info()
    print(f"  Host : {hostname}  |  OS : {distro}  |  Kernel : {kernel}")
    print()

    # Handle sudo
    if args.no_sudo:
        import runner
        runner._sudo_available = False
        print("  [--no-sudo] Skipping all privileged checks.")
        print()
    else:
        check_sudo()

    categories = filter_categories(args)
    if not categories:
        print("  No categories selected. Exiting.")
        sys.exit(1)

    print(f"  Running {len(categories)} check categories...\n")

    all_results_by_category = {}

    for display_name, module_name in categories:
        try:
            import importlib
            mod = importlib.import_module(module_name)
            results = mod.run_all()
        except Exception as e:
            from checks import CheckResult, ERROR
            results = [CheckResult(display_name, "Module error", ERROR,
                                   f"Check module failed: {e}",
                                   "Report this as a bug in netblaze")]

        all_results_by_category[display_name] = results
        print_live_status(display_name, results)

    print()

    # Build and write report
    report = build_report(all_results_by_category, hostname, kernel, distro)
    filepath = write_report(report, output_dir=args.out)

    # Print summary to stdout
    from collections import Counter
    all_results = [r for results in all_results_by_category.values() for r in results]
    counts = Counter(r.status for r in all_results)
    print()
    print(SEPARATOR_WIDE)
    print(f"  Results: {counts.get('ERROR',0)} error(s), "
          f"{counts.get('WARN',0)} warning(s), "
          f"{counts.get('OK',0)} OK, "
          f"{counts.get('INFO',0)} info, "
          f"{counts.get('SKIP',0)} skipped")
    print()
    print(f"  Report written to: {os.path.abspath(filepath)}")
    print(SEPARATOR_WIDE)
    print()

    # Exit code: 2 if errors, 1 if warnings, 0 if clean
    if counts.get("ERROR", 0) > 0:
        sys.exit(2)
    elif counts.get("WARN", 0) > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
