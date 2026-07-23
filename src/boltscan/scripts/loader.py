"""loader.py — Loads preset or custom scripts (.py/.js/.lua/.rs) into a unified callable."""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from importlib import import_module
from typing import Callable

# Maps short preset names to fully-qualified module paths
PRESETS: dict[str, str] = {
    "banner":     "boltscan.scripts.banner_grab",
    "http-title": "boltscan.scripts.http_title",
}

ScriptFunc = Callable[[str, int], str]


def _make_subprocess_runner(cmd_prefix: list[str]) -> ScriptFunc:
    def run(target: str, port: int) -> str:
        # Validate port is in legal range before passing to subprocess
        if not (1 <= port <= 65535):
            return "script error: invalid port"
        cmd = cmd_prefix + [target, str(port)]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5.0,
                shell=False,  # never allow shell expansion
            )
            if result.returncode != 0:
                err = result.stderr.strip() or result.stdout.strip()
                return f"script error: {err[:200]}"
            # Cap output so a malicious server can't flood the results table
            return result.stdout.strip()[:500]
        except subprocess.TimeoutExpired:
            return "script error: timeout after 5s"
        except Exception as e:
            return f"script error: {str(e)[:200]}"

    return run


def _compile_script(script_path: str, compiler: str, lang_name: str) -> str | None:
    """Compile a Rust source file to a binary, using mtime to skip redundant recompilation."""
    if not shutil.which(compiler):
        ext = os.path.splitext(script_path)[1]
        print(
            f"[boltscan] warning: {compiler} not found — required to run "
            f"{ext} scripts. Install {lang_name} and try again.",
            file=sys.stderr,
        )
        return None

    # On Windows the binary needs a .exe extension; on Unix it has none
    binary_ext = ".exe" if os.name == "nt" else ""
    binary_path = (
        os.path.splitext(script_path)[0] + "_compiled" + binary_ext
    )

    # Skip recompilation if the cached binary is newer than the source file
    need_compile = not (
        os.path.exists(binary_path)
        and os.path.getmtime(binary_path) >= os.path.getmtime(script_path)
    )

    if need_compile:
        try:
            subprocess.run(
                [compiler, script_path, "-o", binary_path],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            print(
                f"[boltscan] warning: failed to compile {script_path}:\n"
                f"{e.stderr.strip()}",
                file=sys.stderr,
            )
            return None

    return binary_path


def load_script(script_arg: str) -> ScriptFunc | None:
    """Resolve a preset name or file path to a run(target, port)->str callable; returns None on fail."""
    if not script_arg:
        return None

    # ── Preset lookup ──────────────────────────────────────────────────
    if script_arg in PRESETS:
        try:
            module = import_module(PRESETS[script_arg])
            return getattr(module, "run", None)
        except ImportError:
            return None

    # ── Custom file ────────────────────────────────────────────────────
    script_path = os.path.abspath(script_arg)
    if not os.path.isfile(script_path):
        return None

    ext = os.path.splitext(script_path)[1].lower()

    if ext == ".py":
        # Load the Python script dynamically via importlib so it runs
        # in-process and can be called like a normal function
        stem = os.path.splitext(os.path.basename(script_path))[0]
        module_name = "boltscan_custom_" + stem
        try:
            spec = importlib.util.spec_from_file_location(
                module_name, script_path
            )
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)  # type: ignore[attr-defined]
                func = getattr(module, "run", None)
                if not func:
                    print(
                        f"[boltscan] error: script {script_path} does not "
                        "define a 'run' function.",
                        file=sys.stderr,
                    )
                    sys.exit(1)
                return func
        except Exception as e:
            print(
                f"[boltscan] error: failed to load python script "
                f"{script_path}: {e}",
                file=sys.stderr,
            )
            sys.exit(1)
        return None

    if ext == ".js":
        if not shutil.which("node"):
            print(
                "[boltscan] warning: node not found — required to run "
                ".js scripts. Install Node.js and try again.",
                file=sys.stderr,
            )
            return None
        return _make_subprocess_runner(["node", script_path])

    if ext == ".lua":
        if not shutil.which("lua"):
            print(
                "[boltscan] warning: lua not found — required to run "
                ".lua scripts. Install Lua and try again.",
                file=sys.stderr,
            )
            return None
        return _make_subprocess_runner(["lua", script_path])

    if ext == ".rs":
        binary = _compile_script(script_path, "rustc", "Rust (rustc)")
        return _make_subprocess_runner([binary]) if binary else None

    # Unsupported extension
    print(
        f"[boltscan] warning: unsupported script extension '{ext}' — "
        "supported types are .py, .js, .lua, .rs. Script will not run.",
        file=sys.stderr,
    )
    return None
