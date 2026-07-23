# Boltscan

A fast, easy-to-use **port scanner** for the command line, built in Python.

## What is a port scanner, and why would I use one?

Every device on a network (a laptop, a server, a website) has thousands of
numbered "doors" called **ports**. A service running on that device — a web
server, an SSH login, a database — sits behind one of those doors, listening
for connections. A port scanner simply knocks on a range of doors and reports
back which ones answered ("open") and which didn't ("closed" or "filtered").

People use port scanners to:
- Check which services are exposed on their **own** server or home network
- Verify a firewall is actually blocking what it's supposed to block
- Find forgotten/unused services still running and reachable
- Learn how networking and security tooling works

Boltscan does this quickly, with a clean live progress bar, and can optionally
grab extra details about what's running on each open port (a banner, an HTTP
page title, or a software version).

> ⚠️ **Only scan systems you own or have explicit permission to test.**
> See [Legal / Ethical Use](#legal--ethical-use) below.

## Quick Start

```bash
# 1. Install
pip install .

# 2. Scan your own machine's most common 1024 ports
boltscan -t 127.0.0.1

# 3. Scan a specific device on your network for common web ports
boltscan -t 192.168.1.1 -p 80,443,8080
```

That's it — Boltscan prints a live progress bar while scanning, then a table
of every open port it found, what service normally runs there, and how long
the scan took.

## Features

- **No special privileges needed** — the default scan mode is a normal TCP
  connection, so it works without root/admin rights
- **Nmap-style timing templates** — dial the scan speed from `T0` (very slow
  and quiet) to `T5` (as fast as possible) with a single flag
- **Optional extras on open ports** — grab a service banner, pull the `<title>`
  of a web page, or detect a software version (e.g. `OpenSSH 8.9p1`)
- **Custom scripts** — write your own check in Python, JavaScript, Lua, or
  Rust and run it against every open port Boltscan finds
- **Export to Markdown** — save a shareable report of your scan results
- **Interruptible** — stop a running scan cleanly at any time and still see
  partial results

## Requirements

- Python 3.10 or newer
- `rich` and `pyfiglet` — installed automatically with Boltscan
- **Optional**, only if you want SYN scanning (`-sS`): the `scapy` package,
  root/administrator privileges, and (on Windows) [Npcap](https://npcap.com/)
- **Optional**, only if you run non-Python custom scripts: `node` for `.js`
  scripts, `lua` for `.lua` scripts, or `rustc` for `.rs` scripts

## Installation

```bash
pip install .
```

With SYN scan support:

```bash
pip install ".[syn]"
```

For development (editable install):

```bash
pip install -e .
```

## Basic Usage

```bash
boltscan -t <target> [options]
```

`<target>` can be an IP address (`192.168.1.1`) or a hostname
(`example.com`) — Boltscan resolves hostnames automatically.

### The options you'll actually use most

| Flag | What it does |
|------|--------------|
| `-t / --target` | The IP or hostname to scan **(required)** |
| `-p / --ports` | Which ports to scan: `1-1024` (default), `22,80,443`, or `all` (every port, 1–65535) |
| `-b / --banner` | Try to grab a text "banner" from each open port |
| `-sV / --service-version` | Try to identify the exact software/version behind each open port |
| `-o / --export-md` | Save the results to a Markdown file, e.g. `-o report.md` |
| `-v / --version` | Print the installed Boltscan version |

### Everything else

| Flag | What it does |
|------|--------------|
| `-T0` … `-T5` | Timing template — how fast/slow and how many threads (`T3` is the default, balanced setting) |
| `-th / --threads` | Manually override the thread count from the timing template |
| `--timeout` | How long (in seconds) to wait per connection before giving up |
| `-Pn / --skip-ping` | Skip the "is this host even up?" check and scan directly |
| `-sS / --syn-scan` | Stealthier "half-open" scan — needs root/admin and `scapy` installed |
| `--script` | Run a preset (`banner`, `http-title`) or your own custom script file |

### Stopping a scan early

Press **`Q`** or **Ctrl+Z** while a scan is running to stop it and print
whatever results were found so far. (Ctrl+C is intentionally disabled during
a scan when running in a real terminal, so it can't leave the progress bar in
a broken state — if you pipe Boltscan's input/output or run it in a script,
Ctrl+C works normally instead.)

### Example commands

```bash
# Basic scan of the most common 1024 ports
boltscan -t 192.168.1.1

# Scan every port (1-65535), fast, with banner grabbing
boltscan -t scanme.nmap.org -p all -T4 -b

# Identify software versions on a few key ports
boltscan -t 192.168.1.1 -p 22,80,443 -sV

# Grab the page title from web servers on common web ports
boltscan -t example.com -p 80,443,8080,8443 --script http-title

# Skip the host-is-up check and save results to a report
boltscan -t 192.168.1.1 -Pn -p 1-1024 -o scan_results.md

# Stealthier SYN scan (needs sudo/admin + scapy)
sudo boltscan -t 192.168.1.1 -sS -p 1-1024

# Run your own custom Python check on every open port
boltscan -t 10.0.0.1 -p 1-500 --script /path/to/my_script.py

# Run example scripts in other languages
boltscan -t 192.168.1.1 -p 80 --script examples/scripts/hello.js
boltscan -t 192.168.1.1 -p 80 --script examples/scripts/hello.lua
boltscan -t 192.168.1.1 -p 443 --script examples/scripts/hello.rs
```

## Timing Templates

These control how fast Boltscan scans, borrowed from nmap's `-T` flags.
Slower templates are quieter and less likely to trip alarms or overload a
target; faster templates finish sooner but generate more traffic at once.

| Template | Delay between probes | Threads | Best for |
|----------|----------------------|---------|----------|
| `T0` | 3.0s | 1 | Maximum stealth, very slow |
| `T1` | 0.5s | 10 | Quiet, minimal footprint |
| `T2` | 0.1s | 50 | Polite — won't disrupt normal traffic |
| `T3` | 0.02s | 250 | **Default** — good for typical networks |
| `T4` | 0.005s | 500 | Fast, assumes a reliable network |
| `T5` | 0.0s | 1000 | Fastest, may drop packets on unstable links |

## Custom Scripts

Boltscan can run a script of your own against every open port it finds —
similar in spirit to nmap's NSE scripts. Supported languages: **Python,
JavaScript, Lua, and Rust**.

### Writing a Python script

Create a `.py` file with a `run` function:

```python
def run(target: str, port: int) -> str:
    # your own check goes here
    return "result string"
```

### Writing a script in another language

Non-Python scripts follow a simple contract: Boltscan runs your script/binary
with the target and port as command-line arguments, and captures whatever it
prints to `stdout` as the result.

```bash
node script.js <target> <port>
lua script.lua <target> <port>
./compiled_binary <target> <port>   # Rust scripts are compiled automatically
```

- A script has 5 seconds to finish before Boltscan times it out
- If your script exits with an error, that error is shown in the results table
  instead of a result
- Rust (`.rs`) scripts are compiled once and cached — Boltscan only recompiles
  when the source file changes

### Required tools per language

| Language | File extension | You need installed |
|----------|-----------------|---------------------|
| Python | `.py` | Nothing extra — runs in-process |
| JavaScript | `.js` | `node` |
| Lua | `.lua` | `lua` |
| Rust | `.rs` | `rustc` |

**Security note:** a custom script is just a program that Boltscan runs for
you — only point `--script` at files you wrote yourself or fully trust, the
same way you wouldn't run a random `.exe` or shell script from someone else.

## Service Version Detection (`-sV`)

Instead of just saying "port 22 is open," `-sV` tries to identify exactly what
software is answering:

- **SSH** — reads the banner (e.g. `OpenSSH 8.9p1`)
- **HTTP/HTTPS** — reads the `Server:` header (e.g. `nginx/1.18.0`)
- **FTP / SMTP / POP3 / IMAP** — reads the service's greeting message

```bash
boltscan -t scanme.nmap.org -p 22,80 -sV
```

## Project Structure

```
boltscan/
├── pyproject.toml
├── README.md
├── examples/
│   └── scripts/
│       ├── hello.js        # JavaScript example script
│       ├── hello.lua       # Lua example script
│       └── hello.rs        # Rust example script
└── src/
    └── boltscan/
        ├── __init__.py
        ├── cli.py              # Argument parsing & entry point
        ├── scanner.py          # Core scanning engine (ThreadPoolExecutor)
        ├── timing.py           # T0–T5 timing templates
        ├── ui.py               # Rich terminal UI (progress + summary table)
        ├── ports.py            # Port parsing & service name lookup
        ├── version_detect.py   # Service version detection (-sV)
        ├── syn_scan.py         # TCP SYN scan via scapy (-sS)
        ├── discovery.py        # ICMP/TCP host discovery (-Pn to skip)
        ├── exporter.py         # Markdown report export (-o)
        └── scripts/
            ├── __init__.py
            ├── loader.py       # Preset & custom script loader
            ├── banner_grab.py  # Banner grabbing script
            └── http_title.py   # HTTP <title> extraction script
```

## Legal / Ethical Use

Boltscan is meant for scanning systems and networks **you own, or have
explicit written permission to test.** Port-scanning systems you don't own or
don't have permission to test may be illegal where you live (for example,
under the U.S. Computer Fraud and Abuse Act, or similar laws elsewhere), and
may violate the terms of service of your ISP or hosting provider. You are
solely responsible for how you use this tool.

## License

Apache 2.0 — see [`pyproject.toml`](pyproject.toml) for full author and license details.
