"""
Report builder: formats CheckResult lists into human-readable table-format reports.
"""
import os
import datetime
from checks import CheckResult, OK, WARN, ERROR, SKIP, INFO

STATUS_ICON = {
    OK:    "OK   ",
    WARN:  "WARN ",
    ERROR: "ERROR",
    SKIP:  "SKIP ",
    INFO:  "INFO ",
}

STATUS_ORDER = [ERROR, WARN, INFO, OK, SKIP]

SEPARATOR_WIDE = "=" * 100
SEPARATOR_THIN = "-" * 100


def _col(text, width, align="left"):
    text = str(text)
    if len(text) > width:
        text = text[:width - 3] + "..."
    if align == "right":
        return text.rjust(width)
    elif align == "center":
        return text.center(width)
    return text.ljust(width)


def _table_row(cols, widths, sep="|"):
    parts = [f" {_col(v, w)} " for v, w in zip(cols, widths)]
    return sep + sep.join(parts) + sep


def _table_border(widths, left="+", mid="+", right="+", fill="-"):
    parts = [fill * (w + 2) for w in widths]
    return left + mid.join(parts) + right


def format_category_table(category, results):
    """Return a formatted string for one category's results."""
    lines = []
    lines.append("")
    lines.append(SEPARATOR_WIDE)
    lines.append(f"  CATEGORY: {category.upper()}")
    lines.append(SEPARATOR_WIDE)

    widths = [30, 7, 45, 45]
    headers = ["Item", "Status", "Finding", "Recommendation"]

    lines.append(_table_border(widths))
    lines.append(_table_row(headers, widths))
    lines.append(_table_border(widths, "+", "+", "+", "="))

    # Sort: errors first, then warns, info, ok, skip
    def sort_key(r):
        return STATUS_ORDER.index(r.status) if r.status in STATUS_ORDER else 99

    for result in sorted(results, key=sort_key):
        row = [
            result.item,
            STATUS_ICON.get(result.status, result.status),
            result.finding,
            result.recommendation or "—",
        ]
        # Handle multi-line wrap for long findings/recommendations
        lines.append(_table_row(row, widths))
        lines.append(_table_border(widths))

    return "\n".join(lines)


def format_summary_table(all_results):
    """Return top-level summary table across all categories."""
    from collections import defaultdict, Counter
    category_counts = defaultdict(Counter)
    for r in all_results:
        category_counts[r.category][r.status] += 1

    lines = []
    lines.append("")
    lines.append(SEPARATOR_WIDE)
    lines.append("  NETWORK DIAGNOSTIC SUMMARY")
    lines.append(SEPARATOR_WIDE)

    widths = [22, 6, 6, 7, 6, 6]
    headers = ["Category", "OK", "INFO", "WARN", "ERROR", "SKIP"]
    lines.append(_table_border(widths))
    lines.append(_table_row(headers, widths))
    lines.append(_table_border(widths, "+", "+", "+", "="))

    total = Counter()
    for cat in sorted(category_counts.keys()):
        counts = category_counts[cat]
        row = [
            cat,
            str(counts.get(OK, 0)),
            str(counts.get(INFO, 0)),
            str(counts.get(WARN, 0)),
            str(counts.get(ERROR, 0)),
            str(counts.get(SKIP, 0)),
        ]
        lines.append(_table_row(row, widths))
        lines.append(_table_border(widths))
        for s in [OK, INFO, WARN, ERROR, SKIP]:
            total[s] += counts.get(s, 0)

    lines.append(_table_row(
        ["TOTAL", str(total[OK]), str(total[INFO]),
         str(total[WARN]), str(total[ERROR]), str(total[SKIP])],
        widths
    ))
    lines.append(_table_border(widths))

    # Overall health line
    if total[ERROR] > 0:
        health = f"*** {total[ERROR]} ERROR(S) FOUND — Immediate attention required ***"
    elif total[WARN] > 0:
        health = f"** {total[WARN]} WARNING(S) FOUND — Review recommended **"
    else:
        health = "** No errors or warnings — system looks healthy **"
    lines.append("")
    lines.append(f"  {health}")
    lines.append("")

    return "\n".join(lines)


def format_header(hostname, kernel, distro):
    lines = []
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines.append("")
    lines.append(SEPARATOR_WIDE)
    lines.append("  NETBLAZE — Linux Network Diagnostic Report")
    lines.append(SEPARATOR_WIDE)
    lines.append(f"  Host    : {hostname}")
    lines.append(f"  Kernel  : {kernel}")
    lines.append(f"  OS      : {distro}")
    lines.append(f"  Date    : {now}")
    lines.append(SEPARATOR_WIDE)
    return "\n".join(lines)


def build_report(all_results_by_category, hostname, kernel, distro):
    """Build the complete report string."""
    all_results = [r for results in all_results_by_category.values() for r in results]

    sections = []
    sections.append(format_header(hostname, kernel, distro))
    sections.append(format_summary_table(all_results))

    for category, results in all_results_by_category.items():
        if results:
            sections.append(format_category_table(category, results))

    sections.append("")
    sections.append(SEPARATOR_WIDE)
    sections.append("  END OF REPORT")
    sections.append(SEPARATOR_WIDE)
    sections.append("")

    return "\n".join(sections)


def write_report(report_str, output_dir=None):
    """Write report to a timestamped file. Returns the file path."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    filename = f"network_report_{timestamp}.txt"
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, filename)
    else:
        filepath = filename

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(report_str)
    return filepath


def print_live_status(category, results):
    """Print a compact live status line as each category completes."""
    from collections import Counter
    counts = Counter(r.status for r in results)
    errors = counts.get(ERROR, 0)
    warns = counts.get(WARN, 0)

    if errors:
        badge = f"\033[91m[{errors}E {warns}W]\033[0m"
    elif warns:
        badge = f"\033[93m[{warns}W]\033[0m"
    else:
        badge = f"\033[92m[OK]\033[0m"

    print(f"  {badge}  {category}")
