"""banner_grab.py — Reads service banners via passive wait or HTTP/CRLF probes."""

from __future__ import annotations

import socket

# Probes sent in order; we stop at the first one that gets a response.
# Passive (empty) probe is first: SSH, FTP, SMTP etc. speak without prompting.
_PROBES: list[bytes] = [
    b"",                           # passive — wait for service to speak
    b"HEAD / HTTP/1.0\r\n\r\n",   # HTTP services
    b"\r\n",                       # generic line-feed probe
]
_TIMEOUT = 1.0    # tight enough to stay fast; banner-senders reply quickly
_RECV_SIZE = 512  # first line is always within this; keeps output tidy


def _clean(raw: bytes) -> str:
    """Decode bytes and strip null bytes / non-printable control characters."""
    text = raw.decode(errors="ignore")
    # Preserve tab; strip everything outside printable ASCII range
    cleaned = "".join(ch for ch in text if ch == "\t" or (" " <= ch <= "~"))
    return cleaned.strip()


def run(target: str, port: int) -> str:
    """Attempt to read the service banner; returns 'no banner' on silence."""
    # We test multiple probe types with fresh connections each time.
    # Reusing a single connection would be unreliable — strict protocols
    # like SSH immediately drop connections that send unexpected data
    # (e.g. an HTTP HEAD request). A fresh socket per probe avoids this.
    for probe in _PROBES:
        try:
            # Context manager guarantees the socket is closed after each probe,
            # preventing file-descriptor leaks during high-speed scans.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(_TIMEOUT)
                sock.connect((target, port))

                # Send the probe payload; an empty probe just waits passively
                # to see whether the server speaks first.
                if probe:
                    sock.sendall(probe)

                try:
                    data = sock.recv(_RECV_SIZE)
                except socket.timeout:
                    # This probe got no response within the timeout window.
                    # Try the next probe type before giving up.
                    continue

                if data:
                    banner = _clean(data)
                    first_line = banner.split("\n")[0].strip()
                    if first_line:
                        return first_line

        except (socket.timeout, ConnectionRefusedError, OSError):
            # Connection failed entirely (refused, reset, or unreachable).
            # Skip to the next probe — do not abort the entire scan.
            continue

    # All probes exhausted with no response (normal for RPC/SMB/custom ports)
    return "no banner"
