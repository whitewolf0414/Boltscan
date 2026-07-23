"""boltscan — Core scanning engine: ThreadPoolExecutor + keyboard-interrupt monitor."""

from __future__ import annotations

import concurrent.futures
import random
import signal
import socket
import sys
import threading
import time

from .ports import get_service_name
from .timing import get_timing
from .ui import ScannerUI

_TIMING_LABELS: dict[str, str] = {
    "T0": "T0 (Paranoid)",
    "T1": "T1 (Sneaky)",
    "T2": "T2 (Polite)",
    "T3": "T3 (Normal)",
    "T4": "T4 (Aggressive)",
    "T5": "T5 (Insane)",
}


def _keyboard_monitor(stop_event: threading.Event, ready_event: threading.Event) -> None:
    """Watch stdin for Q / Ctrl+Z and set stop_event to trigger graceful shutdown."""
    # Ctrl+Z = byte 0x1A; Q/q = explicit quit
    _QUIT_BYTES = (b"q", b"Q", b"\x1a")
    _QUIT_CHARS = ("q", "Q", "\x1a")
    try:
        if sys.platform == "win32":
            import msvcrt
            ready_event.set()
            while not stop_event.is_set():
                if msvcrt.kbhit() and msvcrt.getch() in _QUIT_BYTES:
                    stop_event.set()
                    break
                time.sleep(0.05)
        else:
            import select
            import termios
            import tty
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            try:
                tty.setcbreak(fd)
                new = termios.tcgetattr(fd)
                new[3] &= ~termios.ISIG  # disable signal generation (Ctrl+C/Ctrl+Z)
                termios.tcsetattr(fd, termios.TCSADRAIN, new)
                ready_event.set()
                while not stop_event.is_set():
                    if select.select([sys.stdin], [], [], 0.1)[0]:
                        if sys.stdin.read(1) in _QUIT_CHARS:
                            stop_event.set()
                            break
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
    except Exception:
        pass


class Scanner:
    """TCP full-connect scanner; submits one worker thread per port via ThreadPoolExecutor."""

    def __init__(
        self,
        target: str,
        ports: list[int],
        timing_template: str,
        threads: int | None = None,
        timeout: float | None = None,
        script_func=None,
        banner_grab_enabled: bool = False,
        version_detect_enabled: bool = False,
    ) -> None:
        self.target = target
        self.ports = list(ports)
        random.shuffle(self.ports)

        delay, default_threads = get_timing(timing_template)
        self.timing_template = timing_template.upper()
        self.delay = delay
        self.threads = threads if threads is not None else default_threads
        self.timeout = timeout if timeout is not None else max(0.5, 3.0 - self.threads / 200.0)
        self.script_func = script_func
        self.banner_grab_enabled = banner_grab_enabled
        self.version_detect_enabled = version_detect_enabled
        self._jitter = self.delay * 0.5 if self.delay > 0 else 0.0

    def _probe_port(self, port: int) -> bool:
        """Attempt a TCP full-connect; return True if the port is open."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                return sock.connect_ex((self.target, port)) == 0
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def _run_script(self, port: int) -> str:
        """Run the highest-priority enabled script (-sV > --script > -b) on an open port."""
        if self.version_detect_enabled:
            try:
                from .version_detect import detect
                result = detect(self.target, port)
                if result:
                    return result
            except Exception:
                pass

        if self.script_func:
            try:
                return self.script_func(self.target, port) or ""
            except Exception:
                return ""

        if self.banner_grab_enabled:
            from .scripts.loader import load_script
            banner_func = load_script("banner")
            if banner_func:
                try:
                    result = banner_func(self.target, port)
                    return result if result is not None else ""
                except Exception:
                    return ""

        return ""

    def _scan_port(self, port: int, ui: ScannerUI, stop_event: threading.Event) -> None:
        """Worker: probe one port, report to UI, and advance progress; honours stop_event."""
        if stop_event.is_set():
            return
        if self.delay > 0:
            time.sleep(max(0.0, self.delay + random.uniform(-self._jitter, self._jitter)))
        if not stop_event.is_set() and self._probe_port(port):
            ui.add_open_port(port, get_service_name(port), self._run_script(port))
        if not stop_event.is_set():
            ui.update()
            ui.increment_scanned()

    def run(self) -> tuple[list[tuple[int, str, str]], float, int]:
        """Execute the full scan lifecycle; return (open_ports, elapsed_seconds, scanned_count)."""
        import time as _time

        stop_event = threading.Event()
        kb_ready = threading.Event()
        ui = ScannerUI(len(self.ports), self.target)
        ui.print_banner()
        ui.start()

        t_start = _time.perf_counter()
        interrupted = False

        kb_thread = threading.Thread(
            target=_keyboard_monitor, args=(stop_event, kb_ready), daemon=True, name="boltscan-kb-monitor"
        )
        kb_thread.start()
        kb_ready.wait(timeout=1.0)
        self.keyboard_interrupt_available = kb_ready.is_set()

        if self.keyboard_interrupt_available:
            old_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
        else:
            old_handler = None

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.threads)
        try:
            futures = [executor.submit(self._scan_port, p, ui, stop_event) for p in self.ports]
            # Poll in 0.25 s ticks — a single blocking wait() never receives
            # SIGINT on Windows.
            pending = set(futures)
            while pending and not stop_event.is_set():
                _, pending = concurrent.futures.wait(pending, timeout=0.25)
            if stop_event.is_set() and pending:
                interrupted = True
        finally:
            if old_handler is not None:
                signal.signal(signal.SIGINT, old_handler)
            stop_event.set()
            kb_thread.join(timeout=0.5)
            executor.shutdown(wait=interrupted, cancel_futures=interrupted)

        elapsed = _time.perf_counter() - t_start
        ui.stop()
        ui.show_summary(
            elapsed=elapsed,
            timing_label=_TIMING_LABELS.get(self.timing_template, self.timing_template),
            interrupted=interrupted,
        )
        return ui.open_ports, elapsed, ui.scanned_count
