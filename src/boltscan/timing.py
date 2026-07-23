"""timing.py — Nmap-style T0-T5 timing templates (delay and thread count presets)."""

from typing import Tuple

# Dictionary mapping template names to (delay_in_seconds, default_threads).
# Lower templates use longer delays to evade Intrusion Detection Systems (IDS).
TIMING_TEMPLATES: dict[str, Tuple[float, int]] = {
    "T0": (3.0, 1),      # Paranoid  — sequential, long delay for stealth
    "T1": (0.5, 10),     # Sneaky    — slow, small pool for minimal footprint
    "T2": (0.1, 50),     # Polite    — reduced load to avoid disrupting target
    "T3": (0.02, 250),   # Normal    — balanced default for typical networks
    "T4": (0.005, 500),  # Aggressive — fast, assumes reliable network
    # Insane    — full throttle; may drop packets on lossy links
    "T5": (0.0, 1000),
}


def get_timing(template: str) -> tuple[float, int]:
    """Return (delay, threads) for a template string, defaulting to T3 (Normal)."""
    # Use .upper() to ensure case-insensitive matching (e.g., "t3" -> "T3")
    return TIMING_TEMPLATES.get(template.upper(), TIMING_TEMPLATES["T3"])
