"""
ports.py — Port range parsing and common service name lookup.

This module provides functionality to translate human-readable port range strings
(like "80,443,1000-2000") into a list of integers, and to resolve port numbers
to their typical service names (like 80 -> "HTTP").
"""

# Dictionary mapping well-known port numbers to their common service names.
# This avoids the overhead of using socket.getservbyport() and provides
# a consistent mapping regardless of the host operating system's services file.
COMMON_PORTS: dict[int, str] = {
    # ── Basic / Legacy ───────────────────────────────────────────────────
    7: "Echo",
    9: "Discard",
    13: "Daytime",
    17: "QOTD",
    19: "Chargen",
    79: "Finger",
    # ── FTP / File Transfer ─────────────────────────────────────────────
    20: "FTP-Data",
    21: "FTP",
    69: "TFTP",
    989: "FTPS-Data",
    990: "FTPS",
    873: "rsync",
    548: "AFP",
    # ── Remote Access / Shell ───────────────────────────────────────────
    22: "SSH",
    23: "Telnet",
    512: "exec",
    513: "login",
    514: "shell",
    543: "klogin",
    544: "kshell",
    3389: "RDP",
    5900: "VNC",
    5901: "VNC-1",
    5902: "VNC-2",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    5555: "ADB",               # Android Debug Bridge
    # ── Web / HTTP ───────────────────────────────────────────────────────
    80: "HTTP",
    443: "HTTPS",
    554: "RTSP",
    8000: "HTTP-Alt",
    8001: "HTTP-Alt",
    8002: "HTTP-Alt",
    8008: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8081: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9000: "HTTP-Alt",
    # ── Mail ─────────────────────────────────────────────────────────────
    25: "SMTP",
    106: "POP3PW",
    110: "POP3",
    143: "IMAP",
    465: "SMTPS",
    587: "Submission",
    993: "IMAPS",
    995: "POP3S",
    119: "NNTP",
    # ── DNS / NTP / DHCP ─────────────────────────────────────────────────
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    123: "NTP",
    5353: "mDNS",
    # ── Name Services / Auth ─────────────────────────────────────────────
    88: "Kerberos",
    111: "RPCbind",
    135: "MSRPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    389: "LDAP",
    445: "SMB",
    464: "Kerberos-pw",
    500: "ISAKMP",
    593: "RPC-HTTP",
    636: "LDAPS",
    749: "Kerberos-Admin",
    # ── Printing / Misc OS ───────────────────────────────────────────────
    161: "SNMP",
    162: "SNMP-Trap",
    179: "BGP",
    515: "LPD",
    520: "RIP",
    631: "IPP",
    # ── VPN ──────────────────────────────────────────────────────────────
    1194: "OpenVPN",
    1723: "PPTP",
    # ── Proxy / Caching ──────────────────────────────────────────────────
    1080: "SOCKS",
    3128: "Squid-Proxy",
    # ── Databases ────────────────────────────────────────────────────────
    1433: "MSSQL",
    1434: "MSSQL-Browser",
    1521: "Oracle-DB",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    9300: "Elasticsearch-Cluster",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB-shard",
    27019: "MongoDB-arbiter",
    50070: "Hadoop-HDFS",
    # ── Message Queues / Middleware ──────────────────────────────────────
    1099: "Java-RMI",
    2181: "Zookeeper",
    4369: "RabbitMQ",
    5060: "SIP",
    5061: "SIP-TLS",
    5672: "AMQP",
    8161: "ActiveMQ-Web",
    61613: "ActiveMQ-STOMP",
    61616: "ActiveMQ",
    # ── Containers / Orchestration ───────────────────────────────────────
    2375: "Docker",
    2376: "Docker-TLS",
    6443: "Kubernetes-API",
    10250: "Kubelet",
    # ── DevOps / Monitoring ──────────────────────────────────────────────
    2049: "NFS",
    3000: "Grafana",
    8500: "Consul",
    9090: "Prometheus",
    9100: "Prometheus-Node",
    9418: "Git",
    # ── VMware ───────────────────────────────────────────────────────────
    902: "VMware-auth",          # VMware Server / ESXi authentication daemon
    912: "VMware-VIX",           # VMware VIX API (management)
}


def parse_ports(port_str: str) -> list[int]:
    """Parse a port string ("22,80-100", "all") into a sorted, deduplicated list of ints."""
    # If no string is provided, default to the top 1024 ports.
    if not port_str:
        return list(range(1, 1025))

    port_str = port_str.strip().lower()

    # Fast path for scanning all possible TCP ports
    if port_str == "all":
        return list(range(1, 65536))

    ports: set[int] = set()
    # Split by comma to handle mixed format (e.g. "22,80-100")
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                # Split only on the first dash to prevent issues with malformed
                # strings
                start_s, end_s = part.split("-", 1)
                start_p, end_p = int(start_s), int(end_s)
                # Ensure the ports are within valid TCP bounds and the range is
                # logical
                if 1 <= start_p <= 65535 and 1 <= end_p <= 65535 and start_p <= end_p:
                    ports.update(range(start_p, end_p + 1))
            except ValueError:
                # Silently ignore unparseable segments
                pass
        else:
            try:
                p = int(part)
                # Only add valid TCP port numbers
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                # Silently ignore unparseable segments
                pass

    # Sort the set to provide a deterministic order (even though scanner
    # randomises it later)
    return sorted(ports)


def get_service_name(port: int) -> str:
    """Return the common service name for a port, or 'unknown' if not in COMMON_PORTS."""
    return COMMON_PORTS.get(port, "unknown")
