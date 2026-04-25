"""
Command executor with sudo support and timeout handling.
"""
import subprocess
import os
import getpass
import shlex


_sudo_available = None
_sudo_password = None


def check_sudo():
    """Detect sudo availability. Prompt once if needed. Returns True if sudo usable."""
    global _sudo_available, _sudo_password

    if _sudo_available is not None:
        return _sudo_available

    if os.geteuid() == 0:
        _sudo_available = True
        return True

    # Try passwordless sudo
    result = subprocess.run(
        ["sudo", "-n", "true"],
        capture_output=True,
        timeout=5
    )
    if result.returncode == 0:
        _sudo_available = True
        return True

    # Prompt user
    print("\n[netblaze] Some checks require sudo privileges.")
    print("Press Enter to skip privileged checks, or enter your sudo password:")
    try:
        password = getpass.getpass("sudo password (blank to skip): ")
    except (KeyboardInterrupt, EOFError):
        password = ""

    if not password:
        _sudo_available = False
        print("[netblaze] Skipping privileged checks.\n")
        return False

    # Validate password
    proc = subprocess.run(
        ["sudo", "-S", "-v"],
        input=password + "\n",
        capture_output=True,
        text=True,
        timeout=10
    )
    if proc.returncode == 0:
        _sudo_password = password
        _sudo_available = True
        print("[netblaze] sudo access confirmed.\n")
        return True
    else:
        print("[netblaze] Incorrect password or sudo not permitted. Skipping privileged checks.\n")
        _sudo_available = False
        return False


def run(cmd, sudo=False, timeout=10, input_text=None):
    """
    Run a shell command. Returns (stdout, stderr, returncode).
    Returns (None, "SKIP: reason", -2) if skipped.
    Returns (None, "ERROR: reason", -1) on exception.
    """
    if sudo and not check_sudo():
        return (None, "SKIP: requires sudo", -2)

    if isinstance(cmd, str):
        args = shlex.split(cmd)
    else:
        args = list(cmd)

    if sudo and os.geteuid() != 0:
        if _sudo_password:
            args = ["sudo", "-S"] + args
            if input_text is None:
                input_text = _sudo_password + "\n"
            else:
                input_text = _sudo_password + "\n" + input_text
        else:
            args = ["sudo"] + args

    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text
        )
        return (proc.stdout, proc.stderr, proc.returncode)
    except subprocess.TimeoutExpired:
        return (None, f"ERROR: command timed out after {timeout}s", -1)
    except FileNotFoundError:
        return (None, f"ERROR: command not found: {args[0]}", -1)
    except Exception as e:
        return (None, f"ERROR: {e}", -1)


def read_file(path):
    """Read a file, return content or None on failure."""
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except Exception:
        return None


def command_exists(cmd):
    """Check if a command is available on PATH."""
    from shutil import which
    return which(cmd) is not None
