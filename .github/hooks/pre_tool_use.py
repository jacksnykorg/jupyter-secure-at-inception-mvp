#!/usr/bin/env python3
"""
Copilot Hooks (preToolUse) — always-on security gates.

GATE 1 — Notebook execution gate (always enforced, non-negotiable order):
  When an agent tool call would execute a Jupyter notebook or run cells, this
  hook runs **before** that tool is allowed:

    1. Resolve the target ``.ipynb`` path from the tool payload (best-effort).
    2. **Export** — ``python -m nbconvert --to python <notebook.ipynb>`` (fresh
       export every time so the ``.py`` matches the notebook on disk).
    3. **Scan** — ``snyk code test`` on the sibling ``.py`` (Snyk CLI must be on
       ``PATH``; exit code 0 required).

  Only if both steps succeed does the hook return without denying (the blocked
  execution tool then proceeds). If nbconvert fails, Snyk is missing, or Snyk
  reports issues, the tool call is **denied** with a short reason.

  Optional env overrides (seconds):
    ``COPILOT_PRETOOL_NBCONVERT_TIMEOUT`` (default 120),
    ``COPILOT_PRETOOL_SNYK_TIMEOUT`` (default 300).

  On a clean scan, a small voucher file is written under the system temp dir
  (``<tempdir>/.snyk-nb-scan-ok.<sha256-hex16-of-resolved-nb-path>``) for
  optional cross-tool bookkeeping. **Export and Snyk Code run only in this hook.**

GATE 2 — pip install gate (enforced when .cursor/enable-snyk-pip-gate exists):
  Before any pip install, snyk_package_health_check must be called for each
  package. After a health check a one-shot voucher allows the next install.

Payload support:
  Both camelCase (toolName/toolArgs) and VS Code-compatible snake_case
  (tool_name/tool_input) payload formats are normalised before processing.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


# ---------------------------------------------------------------------------
# Regex constants
# ---------------------------------------------------------------------------

_PIP_RE = re.compile(
    r"(?:^|\s)(?:python3?|py)\s+-m\s+pip\s+install\b|"
    r"(?:^|\s)pip3?\s+install\b|"
    r"(?:^|\s)%pip\s+install\b|"
    r"(?:^|\s)!pip3?\s+install\b",
    re.I,
)

_SHELL_TOOLS = frozenset({"bash", "shell", "terminal", "powershell"})

_NOTEBOOK_EXEC_CMD = re.compile(
    r"(?:^|[\s;&|])(?:python3?|py)\s+-m\s+(?:jupyter\s+nbconvert|nbconvert)\b.*(?:\s|^)--execute\b|"
    r"\bjupyter(?:-notebook)?\s+nbconvert\b.*(?:\s|^)--execute\b|"
    r"\bjupyter\s+execute\b|"
    r"\bjupyter\s+run\b|"
    r"\bpapermill\b|"
    r"\bnbclient\b|"
    r"\bipython\b.*\s-c\s",
    re.I | re.S,
)

_TOOLNAME_NOTEBOOK_EXEC = re.compile(
    r"(jupyter|ipython|nbconvert|papermill|nbclient|execute_?cell|run_?cell|notebook_?run|run_?notebook)",
    re.I,
)

_NB_PATH_KEYS = ("path", "notebook", "input", "input_path", "notebook_path", "file", "filePath", "file_path")


# ---------------------------------------------------------------------------
# Helpers shared by both gates
# ---------------------------------------------------------------------------


def _safe_hex(value: str) -> str:
    digest = hashlib.sha256(value.encode()).hexdigest()[:16]
    if not re.match(r"^[0-9a-f]+$", digest):
        raise ValueError("unexpected digest")
    return digest


def _parse_tool_args(tool_args_raw) -> dict:
    if not tool_args_raw:
        return {}
    if isinstance(tool_args_raw, dict):
        return tool_args_raw
    try:
        return json.loads(tool_args_raw)
    except Exception:
        return {}


def _normalize_pre_tool_payload(data: dict) -> tuple[str, str, dict]:
    """Normalise camelCase and VS Code-compatible snake_case payloads."""
    cwd = str(data.get("cwd") or os.getcwd())
    tool_name = str(data.get("toolName") or data.get("tool_name") or "")
    raw_args = data.get("toolArgs")
    if raw_args is None:
        raw_args = data.get("tool_input")
    tool_args = _parse_tool_args(raw_args if isinstance(raw_args, str) else raw_args)
    return cwd, tool_name, tool_args


def _deny(reason: str) -> None:
    print(
        json.dumps({"permissionDecision": "deny", "permissionDecisionReason": reason}),
        flush=True,
    )


def _workspace_root(start: Path) -> Path:
    for p in [start] + list(start.parents):
        if (p / ".git").exists() or (p / ".cursor").exists():
            return p
    return start.parent


# ---------------------------------------------------------------------------
# Gate 1 — notebook execution (export + Snyk before allow)
# ---------------------------------------------------------------------------


def _shell_command(tool_name: str, tool_args: dict) -> str:
    if tool_name.lower() not in _SHELL_TOOLS:
        return ""
    for key in ("command", "cmd", "line", "shell_command"):
        val = tool_args.get(key)
        if isinstance(val, str) and val.strip():
            return val
    return ""


def _looks_like_agent_notebook_cell_execution(tool_name: str, tool_args: dict) -> bool:
    """True when this tool call is plausibly executing notebook/cell code."""
    tn = (tool_name or "").strip()
    if not tn:
        return False
    tnl = tn.lower()
    if tnl in {"view", "glob", "grep", "create", "edit", "ask_user"}:
        return False

    if _TOOLNAME_NOTEBOOK_EXEC.search(tn):
        return True

    cmd = _shell_command(tn, tool_args)
    if cmd and _NOTEBOOK_EXEC_CMD.search(cmd):
        return True

    if tnl in _SHELL_TOOLS:
        blob = json.dumps(tool_args, sort_keys=True, default=str)
        if _NOTEBOOK_EXEC_CMD.search(blob):
            return True

    return False


def _nb_scan_voucher_path(nb_resolved: str) -> Path:
    return Path(tempfile.gettempdir()) / f".snyk-nb-scan-ok.{_safe_hex(nb_resolved)}"


def _extract_nb_path(cwd: str, tool_name: str, tool_args: dict) -> str | None:
    cmd = _shell_command(tool_name, tool_args)
    if cmd:
        m = re.search(r'([^\s"\']+\.ipynb)', cmd, re.I)
        if m:
            p = Path(m.group(1))
            return str(p if p.is_absolute() else Path(cwd) / p)

    for key in _NB_PATH_KEYS:
        val = tool_args.get(key)
        if isinstance(val, str) and val.strip() and val.lower().endswith(".ipynb"):
            p = Path(val)
            return str(p if p.is_absolute() else Path(cwd) / p)

    return None


def _export_and_snyk_scan_before_notebook_execution(cwd: str, tool_name: str, tool_args: dict) -> bool:
    """
    Run nbconvert then snyk code test before allowing notebook execution.
    Returns True if the tool call may proceed; False if denied (stderr already emitted).
    """
    nb_path_str = _extract_nb_path(cwd, tool_name, tool_args)
    if not nb_path_str:
        _deny(
            "Notebook execution blocked: cannot resolve a target .ipynb from this tool call. "
            "Pass an explicit notebook path (e.g. in the shell command) so export + Snyk Code can run first."
        )
        return False

    nb = Path(nb_path_str).expanduser()
    if not nb.is_absolute():
        nb = Path(cwd) / nb
    nb = nb.resolve()

    if not nb.exists():
        _deny(f"Notebook execution blocked: notebook not found at {nb}")
        return False
    if nb.suffix.lower() != ".ipynb":
        _deny("Notebook execution blocked: resolved path is not a .ipynb file.")
        return False

    nbconvert_timeout = int(os.environ.get("COPILOT_PRETOOL_NBCONVERT_TIMEOUT", "120"))
    snyk_timeout = int(os.environ.get("COPILOT_PRETOOL_SNYK_TIMEOUT", "300"))

    try:
        r_nb = subprocess.run(
            [sys.executable, "-m", "nbconvert", "--to", "python", str(nb)],
            cwd=str(nb.parent),
            capture_output=True,
            text=True,
            timeout=nbconvert_timeout,
        )
    except subprocess.TimeoutExpired:
        _deny(f"Notebook execution blocked: nbconvert timed out after {nbconvert_timeout}s.")
        return False
    except OSError as e:
        _deny(f"Notebook execution blocked: nbconvert could not run ({e}).")
        return False

    if r_nb.returncode != 0:
        tail = ((r_nb.stderr or "") + (r_nb.stdout or ""))[-1200:]
        _deny(
            "Notebook execution blocked: nbconvert failed (export to .py is required first). "
            f"exit={r_nb.returncode}. Output tail:\n{tail}"
        )
        return False

    py = nb.with_suffix(".py")
    if not py.exists():
        _deny("Notebook execution blocked: nbconvert succeeded but the expected .py export is missing.")
        return False

    snyk = shutil.which("snyk")
    if not snyk:
        _deny(
            "Notebook execution blocked: Snyk CLI (`snyk`) is not on PATH. "
            "Install/configure Snyk so `snyk code test` can run on the exported .py before execution."
        )
        return False

    root = _workspace_root(nb)
    try:
        r_sy = subprocess.run(
            [snyk, "code", "test", str(py.resolve())],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=snyk_timeout,
        )
    except subprocess.TimeoutExpired:
        _deny(f"Notebook execution blocked: snyk code test timed out after {snyk_timeout}s.")
        return False
    except OSError as e:
        _deny(f"Notebook execution blocked: snyk code test could not run ({e}).")
        return False

    if r_sy.returncode != 0:
        tail = ((r_sy.stderr or "") + (r_sy.stdout or ""))[-1500:]
        _deny(
            "Notebook execution blocked: Snyk Code reported issues on the exported .py "
            f"(exit {r_sy.returncode}). Fix the notebook, then retry. Output tail:\n{tail}"
        )
        return False

    try:
        _nb_scan_voucher_path(str(nb)).touch(exist_ok=True)
    except OSError:
        pass

    return True


# ---------------------------------------------------------------------------
# Gate 2 — pip install
# ---------------------------------------------------------------------------


def _pip_gate_paths(cwd: str) -> tuple[Path, Path]:
    h = _safe_hex(cwd)
    base = Path(tempfile.gettempdir()) / f"copilot-pip-gate-{h}"
    return (base.with_suffix(".pending"), base.with_suffix(".voucher"))


def _pip_gate_enabled(cwd: str) -> bool:
    return (Path(cwd) / ".cursor" / "enable-snyk-pip-gate").is_file()


def _is_health_check(tool_name: str, tool_args: dict) -> bool:
    blob = (tool_name or "") + " " + json.dumps(tool_args, sort_keys=True)
    return "snyk_package_health_check" in blob.lower()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    raw = os.read(0, 1 << 20).decode("utf-8", errors="replace")
    try:
        data = json.loads(raw) if raw.strip() else {}
    except Exception:
        return

    cwd, tool_name, tool_args = _normalize_pre_tool_payload(data)

    if _looks_like_agent_notebook_cell_execution(tool_name, tool_args):
        if not _export_and_snyk_scan_before_notebook_execution(cwd, tool_name, tool_args):
            return

    if not _pip_gate_enabled(cwd):
        return

    pending_path, voucher_path = _pip_gate_paths(cwd)

    if _is_health_check(tool_name, tool_args):
        try:
            if pending_path.exists():
                pending_path.unlink()
            voucher_path.touch(exist_ok=True)
        except OSError:
            pass
        return

    if tool_name.lower() not in _SHELL_TOOLS:
        return

    command = _shell_command(tool_name, tool_args) or str(tool_args.get("command") or "")
    if not command or not _PIP_RE.search(command):
        return

    if voucher_path.exists():
        try:
            voucher_path.unlink()
        except OSError:
            pass
        return

    try:
        pending_path.write_text(command[:2000], encoding="utf-8")
    except OSError:
        pass

    _deny(
        "pip install is blocked by policy. Run `snyk_package_health_check` for each package "
        "(ecosystem: pypi) first, then retry the install."
    )


if __name__ == "__main__":
    main()
