"""http_title.py — Extracts the HTML <title> tag from HTTP services."""

from __future__ import annotations

import re
import socket

_TIMEOUT = 3.0
_RECV_CHUNK = 4096
_MAX_BODY = 64 * 1024  # read at most 64 KB to find the <title>
_TITLE_RE = re.compile(
    r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL
)


def run(target: str, port: int) -> str:
    """Send an HTTP GET request and return the page title if found."""
    try:
        # Context manager ensures the socket is always closed, even on error.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(_TIMEOUT)
            sock.connect((target, port))

            # Minimal HTTP/1.1 GET request.
            # "Connection: close" prevents the server from keeping the
            # connection alive, which would stall recv() indefinitely.
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"User-Agent: boltscan/1.0\r\n"
                f"Accept: text/html\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            sock.sendall(request.encode())

            chunks: list[bytes] = []
            total = 0

            # Read in chunks to avoid loading a massive body into memory.
            # The <title> is almost always within the first few KB of <head>,
            # so we cap at 64 KB and break early when the tag boundary is seen.
            while total < _MAX_BODY:
                chunk = sock.recv(_RECV_CHUNK)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)

                # Early-exit: no need to read further once we have the title
                # or the head section has closed
                if b"</title>" in chunk or b"</head>" in chunk:
                    break

            response_text = b"".join(chunks).decode(errors="ignore")
            match = _TITLE_RE.search(response_text)
            if match:
                title = " ".join(match.group(1).split())
                return f"Title: {title[:200]}"

    except (socket.timeout, ConnectionRefusedError, OSError):
        # Not an HTTP service, or the connection was dropped. Return empty
        # so the results table shows a dash instead of an error message.
        pass

    return ""
