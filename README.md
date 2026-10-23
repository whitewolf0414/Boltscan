# Boltscan

A fast, nmap-inspired Python CLI port scanner with a real-time Rich terminal UI.

[![PyPI version](https://img.shields.io/pypi/v/boltscan.svg)](https://pypi.org/project/boltscan/)
[![Python versions](https://img.shields.io/pypi/pyversions/boltscan.svg)](https://pypi.org/project/boltscan/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://github.com/whitewolf0414/Boltscan/blob/main/LICENSE)

Boltscan is a lightweight, multithreaded command-line port scanner that tests target network ports to see which services are listening ("open"). Designed for quick network audits and reconnaissance, it delivers live progress bars and clean result tables directly in your terminal without requiring root privileges for standard scans.

> ⚠️ **Only scan systems you own or have explicit permission to test.**

## Installation

- **Recommended (pipx)**:
  ```bash
  pipx install boltscan
  ```
- **Or with pip**:
  ```bash
  pip install boltscan
  ```
- **Debian / Ubuntu / Kali / Parrot note**: Plain `pip` fails with an `externally-managed-environment` error; install `pipx` first with `sudo apt install pipx`, run `pipx ensurepath`, reopen the terminal, and use `pipx`.
- **Windows note**: If the `boltscan` command is not recognized on Windows, run `python -m boltscan.cli -t <target>`.
- **Optional SYN scan support**: `pipx install "boltscan[syn]"` (requires root/administrator privileges and Npcap on Windows).

## Quick Start

```bash
# 1. Scan the default top 1024 ports on localhost
boltscan -t 127.0.0.1

# 2. Scan a specific device for common web ports
boltscan -t 192.168.1.1 -p 80,443

# 3. Detect software versions on SSH and HTTP ports
boltscan -t 192.168.1.1 -p 22,80 -sV
```

## All Options

Run `boltscan --help` to see every option available in the CLI.

| Flag | Description |
|------|-------------|
| `-t, --target` | Target IP address or hostname **(required)** |
| `-p, --ports` | Ports to scan: `1-1024` (default), `22,80,443`, or `all` (1–65535) |
| `-sV, --service-version` | Probe open ports to detect software versions |
| `-b, --banner` | Grab service banners from open ports |
| `-o, --export-md` | Export scan results to a Markdown report file |
| `-T0` to `-T5` | Timing template from `T0` (paranoid/slow) to `T5` (insane/fast; default is `T3`) |

## Custom Scripts

Boltscan can execute custom checks written in Python, JavaScript, Lua, or Rust against every open port via `--script <path>`. Python scripts define `def run(target: str, port: int) -> str:` to return output for the results table. **Security note:** Only run scripts you wrote or trust, as they execute directly on your system.

## Legal / Ethical Use

Boltscan is meant for scanning systems and networks **you own, or have explicit written permission to test.** Port-scanning systems you don't own or don't have permission to test may be illegal where you live (for example, under the U.S. Computer Fraud and Abuse Act, or similar laws elsewhere), and may violate the terms of service of your ISP or hosting provider. You are solely responsible for how you use this tool.

## License

Apache License 2.0, [see the LICENSE file](https://github.com/whitewolf0414/Boltscan/blob/main/LICENSE).
