"""discovery.py — Host discovery via ICMP ping and TCP fallback."""

from __future__ import annotations

import ipaddress
import platform
import socket
import subprocess


def is_host_alive(target: str, timeout: float = 2.0) -> bool:
    """Ping the host via ICMP, falling back to common TCP ports if blocked."""
    # Require a valid IP address — the CLI already resolves hostnames before
    # calling this, so a non-IP value here indicates unexpected usage.
    try:
        ipaddress.ip_address(target)
    except ValueError:
        return False

    is_windows = platform.system().lower() == "windows"
    param = "-n" if is_windows else "-c"
    timeout_flag = "-w" if is_windows else "-W"
    t_val = str(int(timeout * 1000)) if is_windows else str(int(timeout))
    command = ["ping", param, "1", timeout_flag, t_val, target]
    try:
        if subprocess.call(command, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL) == 0:
            return True
    except Exception:
        pass

    # 2. TCP Fallback (80, 443, 22)
    # Many modern firewalls drop ICMP echo requests but allow common TCP ports.
    for port in (80, 443, 22):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((target, port)) == 0:
                    return True
        except Exception:
            pass

    return False
