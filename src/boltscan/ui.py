"""ui.py — Rich-powered live progress bar and results table for boltscan."""

from __future__ import annotations

import sys
import threading
from datetime import datetime

import pyfiglet
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich.markup import escape
from rich import box

# ---------------------------------------------------------------------------
# Shared console — all output goes through one instance to avoid interleaving.
# Do NOT pass a custom file= here.  Rich's Console auto-detects the Windows
# native console, calls SetConsoleMode to enable VT processing, and writes
# through WriteConsoleW — which handles Unicode correctly regardless of the
# active OEM code page (CP437 / CP1252).  Wrapping stdout with a manually
# opened UTF-8 file descriptor bypasses that detection and causes mojibake
# and broken ANSI sequences on legacy cmd.exe.
# ---------------------------------------------------------------------------
custom_theme = Theme({
    "progress.elapsed": "grey70",
    "progress.remaining": "grey70",
    "progress.download": "grey70",
})

# Reconfigure stdout to UTF-8 before Rich creates its console.
# On legacy cmd.exe, Python's stdout defaults to the OEM code page
# (CP437 / CP1252).  Rich's LegacyWindowsTerm writes through that
# codec, so any character outside it raises UnicodeEncodeError.
# reconfigure() switches the TextIOWrapper encoding while keeping
# the underlying OS handle intact, which is the safe documented way
# to do this without breaking Rich's console-detection logic.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

console = Console(
    theme=custom_theme,
    highlight=False,
    log_path=False,          # suppress filename:lineno suffix on .log() calls
)


# Version imported lazily to avoid a circular import at module load time.
def _version() -> str:
    try:
        from boltscan import __version__
        return __version__
    except Exception:
        return "1.0.0"


def print_banner() -> None:
    """Renders a sleek, modern UI header with an ASCII logo and version badge."""
    try:
        ascii_art = pyfiglet.figlet_format("BoltScan", font="smslant")
        lines = ascii_art.splitlines()
        # Filter out trailing empty lines to keep spacing clean
        last_non_empty = 0
        for i, line in enumerate(lines):
            if line.strip():
                last_non_empty = i
        lines = lines[:last_non_empty + 1]

        # Modern vertical color gradient: cyan to blue
        gradient_colors = ["#00ffff", "#00d8ff", "#00b2ff", "#008cff"]
        
        styled_art = Text()
        for idx, line in enumerate(lines):
            color = gradient_colors[min(idx, len(gradient_colors) - 1)]
            styled_art.append(line + "\n", style=f"bold {color}")
            
        version_str = f"v{_version()}"
        
        # Info row: PORT SCANNER • vX.Y.Z • RECON ENGINE
        info_text = Text()
        info_text.append("PORT SCANNER", style="bold white")
        info_text.append("  •  ", style="bold cyan")
        info_text.append(version_str, style="bold cyan")
        info_text.append("  •  ", style="bold cyan")
        info_text.append("RECON ENGINE", style="dim italic white")

        console.print(styled_art)
        console.print(info_text)
        console.print(Text("─" * 60, style="dim cyan"))
    except Exception:
        console.print("[bold cyan]BoltScan[/bold cyan]", style="bold")
    console.print()


class ScannerUI:
    """Manages the Rich live progress bar and the post-scan results table."""

    def __init__(self, total_ports: int, target: str) -> None:
        self.total_ports = total_ports
        self.target = target
        self._lock = threading.Lock()
        # (port, service, output)
        self.open_ports: list[tuple[int, str, str]] = []
        # Number of ports whose probe has fully completed (open or closed).
        # Incremented atomically via increment_scanned(); used by show_summary()
        # to print an accurate "N/total ports scanned" footer even on interrupt.
        self.scanned_count: int = 0

        self._progress = Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(style="grey37", complete_style="cyan"),
            TextColumn("[bold grey70]{task.completed}/{task.total}[/bold grey70]"),
            TextColumn("[bold grey70]{task.fields[open_count]}[/bold grey70] [cyan]open[/cyan]"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
            transient=False,
            expand=True,
        )
        self._task_id: TaskID = self._progress.add_task(
            f"Scanning [bold cyan]{self.target}[/bold cyan]",
            total=self.total_ports,
            open_count=0,
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def print_banner(self) -> None:
        """Prints the scan details in a styled header panel before the scan starts."""
        header_content = (
            f"[bold cyan]Target:[/bold cyan] [bold white]{self.target}[/bold white] | "
            f"[bold cyan]Ports:[/bold cyan] [bold white]{self.total_ports}[/bold white]\n"
            f"[dim]Press [bold yellow]Q[/bold yellow] or [bold yellow]Ctrl+Z[/bold yellow] to safely interrupt the scan.[/dim]"
        )
        console.print(Panel(header_content, title="[bold cyan]Scan Configuration[/bold cyan]", border_style="cyan", box=box.ROUNDED, expand=False))
        console.print()

    def start(self) -> None:
        """Starts the live progress display."""
        self._progress.start()

    def update(self, count: int = 1) -> None:
        """Advance the Rich progress bar by count steps (thread-safe natively)."""
        self._progress.advance(self._task_id, count)

    def increment_scanned(self) -> None:
        """Atomically increment scanned_count; used for accurate footer on interrupt."""
        with self._lock:
            self.scanned_count += 1

    def add_open_port(self, port: int, service: str, script_output: str) -> None:
        """Record an open port, print it live to console, and update the open-port counter."""
        with self._lock:
            self.open_ports.append((port, service, script_output))
            # Use console.print() with a hand-built timestamp instead of
            # console.log() — rich's .log() appends "filename:lineno" at the
            # end of every line (the "ui.py:111" noise), which can't be
            # suppressed per-call and clutters the scan output.
            ts = datetime.now().strftime("%H:%M:%S")
            banner_snippet = ""
            if script_output and script_output != "no banner":
                # Avoid cutting off banners mid-word in the inline log if
                # possible
                if len(script_output) > 72:
                    trunc = script_output[:72]
                    last_space = trunc.rfind(" ")
                    if last_space > 0:
                        trunc = trunc[:last_space]
                    banner_snippet = f"  [dim]{escape(trunc)}…[/dim]"
                else:
                    banner_snippet = f"  [dim]{escape(script_output)}[/dim]"
            elif script_output == "no banner":
                banner_snippet = "  [dim italic]no banner[/dim italic]"
            console.print(
                f"[dim][[/dim][grey62]{ts}[/grey62][dim]][/dim] "
                f"[bold green]  OPEN[/bold green]  "
                f"[cyan]{port:>5}[/cyan]/tcp  "
                f"[bold cyan]{escape(service):<16}[/bold cyan]"
                + banner_snippet
            )
            self._progress.update(
                self._task_id, open_count=len(
                    self.open_ports))

    def stop(self) -> None:
        """Stops the progress display."""
        self._progress.stop()

    def show_summary(
        self,
        elapsed: float | None = None,
        timing_label: str | None = None,
        interrupted: bool = False,
    ) -> None:
        """Render the final results table; shows partial results and a warning if interrupted."""
        console.print()

        if interrupted:
            console.print(
                Panel(
                    "[bold yellow]Scan interrupted by user[/bold yellow]  "
                    "[dim]— partial results shown below[/dim]",
                    border_style="yellow",
                    expand=False,
                )
            )
            console.print()

        if not self.open_ports:
            console.print(
                Panel(
                    f"[bold red]No open ports found on [bold white]{self.target}[/bold white][/bold red]",
                    border_style="red",
                    expand=False,
                )
            )
            return

        # ── Results table ─────────────────────────────────────────────────
        table = Table(
            title=f" Scan Results — {self.target} ",
            title_style="bold cyan",
            box=box.ROUNDED,
            show_lines=True,
            border_style="cyan",
            header_style="bold cyan",
            padding=(0, 1),
            expand=True,
        )
        table.add_column("PORT", justify="right", style="cyan", min_width=6, no_wrap=True)
        table.add_column("PROTO", justify="center", style="dim cyan", min_width=6, no_wrap=True)
        table.add_column("STATE", justify="center", min_width=8, no_wrap=True)
        table.add_column("SERVICE", justify="left", style="bold cyan", min_width=14)
        table.add_column("SCRIPT OUTPUT / BANNER", style="cyan")

        for i, (port, service, output) in enumerate(
            sorted(self.open_ports, key=lambda x: x[0])
        ):
            # Render banner output with appropriate styling:
            #   "no banner" sentinel → dim italic (ran, got silence)
            #   real banner text    → sky_blue1
            #   empty string        → em dash (script not invoked)
            if output == "no banner":
                display_output = Text("no banner", style="dim italic")
            elif output:
                display_output = Text(output, style="cyan")
            else:
                display_output = Text("—", style="dim")

            # Subtle alternating row shading for readability
            row_style = "on grey7" if i % 2 == 0 else ""

            table.add_row(
                str(port),
                "tcp",
                Text("open", style="bold green"),
                escape(service),
                display_output,
                style=row_style,
            )

        console.print(table)

        # ── Footer stats ───────────────────────────────────────────────
        console.print(Rule(style="grey35"))

        # Show "N/total" when interrupted so the user sees how far we got;
        # show just "total" when the full scan completed normally.
        if interrupted:
            scanned_label = (
                f"[bold white]{self.scanned_count}/{self.total_ports}[/bold white]"
                " [cyan]port(s) scanned[/cyan]"
            )
        else:
            scanned_label = (
                f"[bold white]{self.total_ports}[/bold white]"
                " [cyan]port(s) scanned[/cyan]"
            )

        stats_parts = [
            f"[bold white]{len(self.open_ports)}[/bold white]"
            " [cyan]open port(s)[/cyan]",
            scanned_label,
        ]
        if elapsed is not None:
            stats_parts.append(
                f"[bold white]{elapsed:.2f}s[/bold white]"
                " [cyan]elapsed[/cyan]"
            )
        if timing_label is not None:
            stats_parts.append(
                f"[dim]Timing:[/dim]"
                f" [bold cyan]{timing_label}[/bold cyan]"
            )

        console.print(
            "  " +
            "  [dim grey35]·[/dim grey35]  ".join(
                f"[dim]{s}[/dim]" for s in stats_parts)
        )
        console.print()
