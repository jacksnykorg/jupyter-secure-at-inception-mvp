#!/usr/bin/env python3
"""
Copilot Hooks (postToolUse):

- After an agent edits/creates a *.ipynb file, export it to a sibling *.py via nbconvert.
- Optionally run `snyk code test` on the exported file when SNYK_CODE_TEST_ON_EXPORT is truthy.

Notes:
- Copilot Hooks currently ignore output for postToolUse; this script is side-effect only.
- We fail open: export/scan errors should not block the agent session.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _parse_tool_args(tool_args_raw) -> dict:
    if not tool_args_raw:
        return {}
    if isinstance(tool_args_raw, dict):
        return tool_args_raw
    try:
        return json.loads(tool_args_raw)
    except Exception:
        return {}


def _extract_path(tool_args: dict) -> str | None:
    for k in ("path", "filePath", "file_path"):
        v = tool_args.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def _workspace_root(start: Path) -> Path:
    for p in [start] + list(start.parents):
        if (p / ".cursor").exists() or (p / ".git").exists():
            return p
    return start.parent


def main() -> None:
    raw = os.read(0, 1 << 20).decode("utf-8", errors="replace")
    try:
        data = json.loads(raw) if raw.strip() else {}
    except Exception:
        return

    tool_name = str(data.get("toolName") or "").lower()
    # We only care about file-editing tools.
    if tool_name not in {"edit", "create", "write_file", "apply_patch"}:
        return

    tool_args = _parse_tool_args(data.get("toolArgs"))
    path_str = _extract_path(tool_args)
    if not path_str or not path_str.endswith(".ipynb"):
        return

    nb = Path(path_str).expanduser()
    if not nb.is_absolute():
        # Copilot tools often pass relative paths; resolve from cwd.
        nb = Path(str(data.get("cwd") or os.getcwd())) / nb
    nb = nb.resolve()
    if not nb.exists():
        return

    root = _workspace_root(nb)

    try:
        r = subprocess.run(
            [sys.executable, "-m", "nbconvert", "--to", "python", str(nb)],
            cwd=str(nb.parent),
            capture_output=True,
            text=True,
            timeout=120,
        )
        if r.returncode != 0:
            return
    except OSError:
        return

    py_path = nb.with_suffix(".py")
    if not py_path.exists():
        return

    if not _truthy("SNYK_CODE_TEST_ON_EXPORT"):
        return

    snyk = shutil.which("snyk")
    if not snyk:
        return

    try:
        subprocess.run(
            [snyk, "code", "test", str(py_path.resolve())],
            cwd=str(root),
            text=True,
            timeout=120,
        )
    except OSError:
        return


if __name__ == "__main__":
    main()

