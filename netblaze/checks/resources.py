"""
Resource exhaustion checks: FDs, sockets, memory, disk, CPU steal, IRQ balance, softirq drops.
"""
import re
from checks import CheckResult, OK, WARN, ERROR, SKIP, INFO
from runner import run, read_file

CATEGORY = "Resources"

DISK_WARN_PCT = 90
FD_WARN_PCT = 80
IRQ_SINGLE_CPU_WARN = 5   # warn if >5 NIC IRQs are pinned to cpu0 only


def check_disk_space():
    results = []
    stdout, _, rc = run("df -h")
    if rc != 0 or not stdout:
        results.append(CheckResult(CATEGORY, "Disk space", SKIP, "df -h failed"))
        return results

    for line in stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        try:
            use_pct = int(parts[4].rstrip("%"))
            mount = parts[5]
            if use_pct >= DISK_WARN_PCT:
                results.append(CheckResult(CATEGORY, f"Disk ({mount})", ERROR,
                                           f"{parts[4]} used on {mount} ({parts[0]})",
                                           "Disk full can prevent logging, crash daemons; "
                                           "clear old logs/cores or expand volume"))
            elif use_pct >= 75:
                results.append(CheckResult(CATEGORY, f"Disk ({mount})", WARN,
                                           f"{parts[4]} used on {mount}"))
            else:
                results.append(CheckResult(CATEGORY, f"Disk ({mount})", OK,
                                           f"{parts[4]} used on {mount}"))
        except (ValueError, IndexError):
            pass
    return results


def check_fd_exhaustion():
    results = []
    content = read_file("/proc/sys/fs/file-nr")
    if not content:
        return results

    parts = content.split()
    if len(parts) >= 3:
        try:
            allocated = int(parts[0])
            maximum = int(parts[2])
            pct = (allocated / maximum) * 100 if maximum > 0 else 0
            if pct > FD_WARN_PCT:
                results.append(CheckResult(CATEGORY, "FD exhaustion", ERROR,
                                           f"{allocated}/{maximum} file descriptors in use ({pct:.1f}%)",
                                           "Increase: sysctl -w fs.file-max=" + str(maximum * 2)))
            elif pct > 60:
                results.append(CheckResult(CATEGORY, "FD usage", WARN,
                                           f"{allocated}/{maximum} FDs ({pct:.1f}%)"))
            else:
                results.append(CheckResult(CATEGORY, "FD usage", OK,
                                           f"{allocated}/{maximum} FDs ({pct:.1f}%)"))
        except ValueError:
            pass
    return results


def check_cpu_steal():
    results = []
    stdout, _, rc = run("vmstat 1 2")
    if rc != 0 or not stdout:
        return results

    lines = [l for l in stdout.splitlines() if l.strip() and not l.startswith("procs")]
    # vmstat output columns: r b swpd free buff cache si so bi bo in cs us sy id wa st
    for line in lines[-1:]:
        parts = line.split()
        if len(parts) >= 17:
            try:
                steal = int(parts[16])
                if steal > 10:
                    results.append(CheckResult(CATEGORY, "CPU steal (VM)", ERROR,
                                               f"CPU steal={steal}% (hypervisor stealing CPU time)",
                                               "High steal indicates noisy neighbour or overcommitted hypervisor; "
                                               "contact cloud provider or migrate to dedicated host"))
                elif steal > 5:
                    results.append(CheckResult(CATEGORY, "CPU steal (VM)", WARN,
                                               f"CPU steal={steal}%",
                                               "Moderate CPU steal may impact network processing latency"))
                else:
                    results.append(CheckResult(CATEGORY, "CPU steal", OK, f"CPU steal={steal}%"))
            except (ValueError, IndexError):
                pass
    return results


def check_irq_balance():
    results = []
    content = read_file("/proc/interrupts")
    if not content:
        results.append(CheckResult(CATEGORY, "IRQ balance", SKIP, "/proc/interrupts not readable"))
        return results

    header = content.splitlines()[0]
    cpus = header.split()
    num_cpus = len(cpus)

    if num_cpus <= 1:
        results.append(CheckResult(CATEGORY, "IRQ balance", INFO,
                                   "Single CPU system; IRQ balance not applicable"))
        return results

    nic_irqs_on_cpu0_only = 0
    for line in content.splitlines()[1:]:
        parts = line.split()
        if len(parts) < num_cpus + 2:
            continue
        irq_name = parts[-1].lower()
        if any(k in irq_name for k in ["eth", "ens", "enp", "eno", "mlx", "ixgbe", "igb", "virtio-net"]):
            counts = parts[1:num_cpus + 1]
            try:
                int_counts = [int(c) for c in counts]
                if sum(int_counts) > 0:
                    # Check if all on cpu0
                    if int_counts[0] > 0 and all(c == 0 for c in int_counts[1:]):
                        nic_irqs_on_cpu0_only += 1
            except ValueError:
                pass

    if nic_irqs_on_cpu0_only > IRQ_SINGLE_CPU_WARN:
        results.append(CheckResult(CATEGORY, "IRQ balance", WARN,
                                   f"{nic_irqs_on_cpu0_only} NIC IRQ(s) pinned to CPU0 only",
                                   "Install irqbalance or manually spread NIC IRQs: "
                                   "echo <cpumask> > /proc/irq/<N>/smp_affinity"))
    else:
        results.append(CheckResult(CATEGORY, "IRQ balance", OK,
                                   f"NIC IRQs distributed across {num_cpus} CPU(s)"))
    return results


def check_softirq_drops():
    results = []
    content = read_file("/proc/net/softnet_stat")
    if not content:
        results.append(CheckResult(CATEGORY, "Softirq drops", SKIP, "/proc/net/softnet_stat not readable"))
        return results

    total_dropped = 0
    total_squeezed = 0
    for line in content.splitlines():
        cols = line.split()
        if len(cols) >= 3:
            try:
                total_dropped += int(cols[1], 16)
                total_squeezed += int(cols[2], 16)
            except ValueError:
                pass

    if total_dropped > 0:
        results.append(CheckResult(CATEGORY, "Softirq drops", WARN,
                                   f"softnet_stat total dropped={total_dropped}",
                                   "Packets dropped in kernel softirq; increase net.core.netdev_max_backlog: "
                                   "sysctl -w net.core.netdev_max_backlog=5000"))
    else:
        results.append(CheckResult(CATEGORY, "Softirq drops", OK, "No softirq drops"))

    if total_squeezed > 0:
        results.append(CheckResult(CATEGORY, "Softirq budget exceeded", INFO,
                                   f"softnet_stat squeezed={total_squeezed} (NAPI budget exceeded)",
                                   "Increase net.core.netdev_budget or netdev_budget_usecs if sustained"))
    return results


def check_socket_limits():
    results = []
    out, _, rc = run("sysctl -n net.core.somaxconn")
    if rc == 0 and out:
        val = int(out.strip())
        if val < 1024:
            results.append(CheckResult(CATEGORY, "Socket backlog (somaxconn)", WARN,
                                       f"net.core.somaxconn={val} (low for high-traffic servers)",
                                       "Increase: sysctl -w net.core.somaxconn=4096"))
        else:
            results.append(CheckResult(CATEGORY, "Socket backlog (somaxconn)", OK,
                                       f"net.core.somaxconn={val}"))
    return results


def run_all():
    results = []
    results += check_disk_space()
    results += check_fd_exhaustion()
    results += check_cpu_steal()
    results += check_irq_balance()
    results += check_softirq_drops()
    results += check_socket_limits()
    return results
