#!/usr/bin/env python3
"""
Copilot Hooks (preToolUse):

- Enforce "Snyk package health check BEFORE pip install" when the gate flag exists:
  `.cursor/enable-snyk-pip-gate` (empty file).

This is a best-effort port of `.cursor/hooks/pip_install_gate.py` for Copilot Hooks.
Copilot Hooks input/output differs from Cursor Hooks, so we keep logic simple:

- If a pip install is about to run, deny it until a "health check" is observed.
- After a health check, allow exactly one subsequent pip install (voucher).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path


_PIP_RE = re.compile(
    r"(?:^|\s)(?:python3?|py)\s+-m\s+pip\s+install\b|"
    r"(?:^|\s)pip3?\s+install\b|"
    r"(?:^|\s)%pip\s+install\b|"
    r"(?:^|\s)!pip3?\s+install\b",
    re.I,
)


def _safe_hex(value: str) -> str:
    digest = hashlib.sha256(value.encode()).hexdigest()[:16]
    if not re.match(r"^[0-9a-f]+$", digest):
        raise ValueError("unexpected digest")
    return digest


def _state_paths(cwd: str) -> tuple[Path, Path]:
    h = _safe_hex(cwd)
    base = Path(tempfile.gettempdir()) / f"copilot-pip-gate-{h}"
    return (base.with_suffix(".pending"), base.with_suffix(".voucher"))


def _gate_enabled(cwd: str) -> bool:
    # Mirror the Cursor behavior: gate is enabled by this flag file.
    return (Path(cwd) / ".cursor" / "enable-snyk-pip-gate").is_file()


def _parse_tool_args(tool_args_raw: str) -> dict:
    if not tool_args_raw:
        return {}
    if isinstance(tool_args_raw, dict):
        return tool_args_raw
    try:
        return json.loads(tool_args_raw)
    except Exception:
        return {}


def _is_health_check(tool_name: str, tool_args: dict) -> bool:
    # Tool naming varies by Copilot surface. We detect by substring in either:
    # - tool name
    # - tool args (stringified)
    blob = (tool_name or "") + " " + json.dumps(tool_args, sort_keys=True)
    return "snyk_package_health_check" in blob.lower()


def _deny(reason: str) -> None:
    # Hooks config reference: only "deny" is guaranteed to be processed.
    print(
        json.dumps(
            {
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        ),
        flush=True,
    )


def main() -> None:
    raw = os.read(0, 1 << 20).decode("utf-8", errors="replace")
    try:
        data = json.loads(raw) if raw.strip() else {}
    except Exception:
        return

    cwd = str(data.get("cwd") or os.getcwd())
    tool_name = str(data.get("toolName") or "")
    tool_args_raw = data.get("toolArgs") or ""
    tool_args = _parse_tool_args(tool_args_raw if isinstance(tool_args_raw, str) else tool_args_raw)

    pending_path, voucher_path = _state_paths(cwd)

    # If gate not enabled: do nothing (allow).
    if not _gate_enabled(cwd):
        return

    # If we observe a health check, clear pending and grant a voucher.
    if _is_health_check(tool_name, tool_args):
        try:
            if pending_path.exists():
                pending_path.unlink()
            voucher_path.touch(exist_ok=True)
        except OSError:
            pass
        return

    # Only enforce for bash-like tools where a command is being executed.
    if tool_name.lower() not in {"bash", "shell", "terminal"}:
        return

    command = str(tool_args.get("command") or "")
    if not command or not _PIP_RE.search(command):
        return

    # One-shot allow if voucher exists.
    if voucher_path.exists():
        try:
            voucher_path.unlink()
        except OSError:
            pass
        return

    # Otherwise deny and mark pending.
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

