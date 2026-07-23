from __future__ import annotations

import argparse
import os
import socket
import sys

from . import __version__
from .discovery import is_host_alive
from .exporter import export_to_markdown
from .ports import parse_ports
from .scanner import Scanner
from .scripts.loader import load_script
from .ui import print_banner


def _is_admin() -> bool:
    """Return True if the current process has administrator/root privileges."""
    if os.name == "nt":
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _build_parser() -> argparse.ArgumentParser:
    """Construct and configure the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="boltscan",
        description="Boltscan -- fast Python CLI port scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  boltscan -t 192.168.1.1
  boltscan -t scanme.nmap.org -p all -T4 -b
  boltscan -t example.com -p 80,443,8080 --script http-title
  boltscan -t 192.168.1.1 -p 22,80,443 -sV
  boltscan -t 192.168.1.1 -p 80 --script examples/scripts/hello.js
  boltscan -t 192.168.1.1 -p 80 --script examples/scripts/hello.lua
  boltscan -t 192.168.1.1 -p 443 --script examples/scripts/hello.rs
        """,
    )

    parser.add_argument("-t", "--target", required=True, help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-1024", metavar="PORTS",
                        help='Port range: "1-1024" (default), "22,80,443", or "all"')
    parser.add_argument("-sS", "--syn-scan", action="store_true",
                        help="TCP SYN scan (requires root/administrator)")
    parser.add_argument("-Pn", "--skip-ping", action="store_true",
                        help="Skip host discovery and scan directly")

    tg = parser.add_mutually_exclusive_group()
    for flag, desc in [
        ("T0", "Paranoid  -- 3.0s delay, 1 thread"),
        ("T1", "Sneaky    -- 0.5s delay, 10 threads"),
        ("T2", "Polite    -- 0.1s delay, 50 threads"),
        ("T3", "Normal    -- 0.02s delay, 250 threads (default)"),
        ("T4", "Aggressive -- 0.005s delay, 500 threads"),
        ("T5", "Insane    -- 0.0s delay, 1000 threads"),
    ]:
        tg.add_argument(f"-{flag}", action="store_const", const=flag, dest="timing", help=desc)

    parser.add_argument("-th", "--threads", type=int, metavar="N",
                        help="Override thread count from timing template")
    parser.add_argument("--timeout", type=float, metavar="SEC",
                        help="Per-connection timeout in seconds")
    parser.add_argument("-b", "--banner", action="store_true",
                        help="Enable banner grabbing on open ports")
    parser.add_argument("--script", metavar="NAME|PATH",
                        help='Preset ("banner", "http-title") or path to custom script')
    parser.add_argument("-sV", "--service-version", action="store_true", dest="service_version",
                        help="Probe open ports for service version info")
    parser.add_argument("-o", "--export-md", metavar="PATH",
                        help="Export scan results to a Markdown file")
    parser.add_argument("-v", "--version", action="version", version=f"Bolt Scan v{__version__}")
    return parser


_TIMING_NAMES = {
    "T0": "Paranoid", "T1": "Sneaky", "T2": "Polite",
    "T3": "Normal",   "T4": "Aggressive", "T5": "Insane",
}


def main() -> None:
    """CLI entry point: parse args, resolve targets, and orchestrate the scan."""
    print_banner()
    args = _build_parser().parse_args()
    timing = args.timing or "T3"

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[boltscan] error: could not resolve '{args.target}'", file=sys.stderr)
        sys.exit(1)

    if not args.skip_ping and not is_host_alive(target_ip):
        print(
            f"[boltscan] warning: host {args.target} appears down. Use -Pn to scan anyway.",
            file=sys.stderr,
        )
        sys.exit(0)

    ports = parse_ports(args.ports)
    if not ports:
        print("[boltscan] error: no valid ports in range", file=sys.stderr)
        sys.exit(1)

    scanner_cls = Scanner
    if args.syn_scan:
        if not _is_admin():
            print(
                "[boltscan] error: -sS requires root/administrator privileges.",
                file=sys.stderr,
            )
            sys.exit(1)
        try:
            from .syn_scan import SynScanner
            scanner_cls = SynScanner
        except ImportError:
            print("[boltscan] error: scapy is not installed.", file=sys.stderr)
            sys.exit(1)

    script_func = None
    if args.script:
        script_func = load_script(args.script)
        if script_func is None and not os.path.isfile(args.script) \
                and args.script not in ("banner", "http-title"):
            print(f"[boltscan] error: could not load script '{args.script}'", file=sys.stderr)
            sys.exit(1)

    scanner = scanner_cls(
        target=target_ip,
        ports=ports,
        timing_template=timing,
        threads=args.threads,
        timeout=args.timeout,
        script_func=script_func,
        banner_grab_enabled=args.banner,
        version_detect_enabled=args.service_version,
    )
    results, elapsed, scanned_count = scanner.run()
    interrupted = scanned_count < len(ports)

    if args.export_md:
        metadata = {
            "target": args.target,
            "resolved_ip": target_ip,
            "timing_template": timing,
            "timing_name": _TIMING_NAMES.get(timing, "Unknown"),
            "port_count": len(ports),
            "scanned_count": scanned_count,
            "elapsed_time": f"{elapsed:.2f}",
            "version": __version__,
            "interrupted": str(interrupted),
        }
        export_to_markdown(results, metadata, args.export_md)
        out_name = args.export_md if args.export_md.endswith(".md") else args.export_md + ".md"
        print(f"Report saved to: {out_name}")

    if interrupted:
        sys.exit(130)


if __name__ == "__main__":
    main()
