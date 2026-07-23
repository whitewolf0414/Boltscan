"""version_detect.py — Service version fingerprinting for the -sV flag."""

from __future__ import annotations

import re
import socket

_TIMEOUT = 2.0
_RECV_SIZE = 1024
# Extracts the Server header value from an HTTP response
_SERVER_RE = re.compile(r"^Server:\s*(.+)$", re.IGNORECASE | re.MULTILINE)

_HTTP_PORTS = {80, 443, 8000, 8001, 8008, 8080, 8081, 8443, 8888, 9000}
_SSH_PORTS = {22}
_BANNER_PORTS = {21, 25, 110, 143, 587, 993, 995, 119}


def _recv_banner(sock: socket.socket) -> str:
    try:
        raw = sock.recv(_RECV_SIZE)
    except socket.timeout:
        return ""
    if not raw:
        return ""
    text = raw.decode(errors="ignore")
    return "".join(ch for ch in text if ch >= " " or ch == "\t").strip()


def _detect_ssh(target: str, port: int) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(_TIMEOUT)
            sock.connect((target, port))
            match = re.match(r"SSH-[\d.]+-(\S+)", _recv_banner(sock))
            if match:
                return match.group(1).replace("_", " ")
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return ""


def _detect_http(target: str, port: int) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(_TIMEOUT)
            sock.connect((target, port))
            sock.sendall(f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode())
            try:
                response = sock.recv(2048).decode(errors="ignore")
            except socket.timeout:
                return ""
            match = _SERVER_RE.search(response)
            return match.group(1).strip() if match else ""
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return ""


def _detect_banner_service(target: str, port: int) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(_TIMEOUT)
            sock.connect((target, port))
            banner = _recv_banner(sock)
            if banner:
                first_line = re.sub(r"^\d{3}[-\s]", "", banner.split("\n")[0].strip()).strip()
                return first_line[:80]
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return ""


def detect(target: str, port: int) -> str:
    if port in _SSH_PORTS:
        return _detect_ssh(target, port)
    if port in _HTTP_PORTS:
        result = _detect_http(target, port)
        if result:
            return result
    return _detect_banner_service(target, port)
