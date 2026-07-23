"""syn_scan.py — TCP SYN ("half-open") scanning using raw sockets."""

from __future__ import annotations

from .scanner import Scanner

try:
    import scapy.all as scapy  # type: ignore
except ImportError:
    scapy = None


class SynScanner(Scanner):
    """Overrides the default TCP connect scanner to perform stealthy SYN scans via scapy."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Cap SYN scan concurrency to avoid dropping packets/breaking scapy state
        self.threads = min(self.threads, 50)
        self._npcap_warned = False

    def _probe_port(self, port: int) -> bool:
        """Send a TCP SYN packet and return True if a SYN-ACK is received."""
        if scapy is None:
            # scapy is required but missing
            return False

        try:
            # Send SYN packet and wait for 1 response
            ans = scapy.sr1(
                scapy.IP(dst=self.target) / scapy.TCP(dport=port, flags="S"),
                timeout=self.timeout,
                verbose=0
            )
            if ans and ans.haslayer(scapy.TCP):
                # 0x12 is the flag combination for SYN (0x02) | ACK (0x10)
                if ans.getlayer(scapy.TCP).flags & 0x12 == 0x12:
                    # Send RST to properly tear down the embryonic connection
                    rst = scapy.IP(dst=self.target) / \
                        scapy.TCP(dport=port, flags="R", seq=ans.ack)
                    scapy.send(rst, verbose=0)
                    return True
        except Exception as e:
            # Detect a missing Npcap/permission failure specifically
            import sys
            if sys.platform == "win32" and isinstance(e, OSError):
                if not getattr(self, "_npcap_warned", False):
                    print(
                        "\n[boltscan] error: raw packet send failed "
                        "\u2014 is Npcap installed?",
                        file=sys.stderr,
                    )
                    self._npcap_warned = True
            # Catch scapy/socket level errors silently as in normal scanner
            pass

        return False
