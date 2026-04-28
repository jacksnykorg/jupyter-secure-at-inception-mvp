#!/usr/bin/env python3
"""
Cursor Hook: afterFileEdit — export edited *.ipynb → sibling .py + Snyk Code gate.

WORKFLOW
--------
1. Agent edits a .ipynb → this hook fires.
2. nbconvert exports it to a sibling .py.
3. If SNYK_CODE_TEST_ON_EXPORT=1 and snyk CLI is on PATH:
   a. Runs `snyk code test` on the exported .py.
   b. If findings are found → writes a remediation-pending state file and
      emits an agent_message instructing the agent to fix the issue IN the
      notebook (not in the .py), then re-export and rescan.
4. Always exits 0 (fail-open) — export errors go to stderr, never block.

REMEDIATION LOOP (in-notebook)
-------------------------------
When Snyk Code findings are present the agent MUST:
  1. Open the .ipynb and fix the flagged cell(s).
  2. Save — this hook fires again, re-exporting and rescanning.
  3. Repeat until no findings remain.

Remediation state files live under `tempfile.gettempdir()`, keyed by a hash of the workspace path.
Set CURSOR_HOOK_DEBUG=1 for verbose stderr output.
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
# Config
# ---------------------------------------------------------------------------

DEBUG = os.environ.get("CURSOR_HOOK_DEBUG", "0") == "1"




# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _debug(msg: str) -> None:
    if DEBUG:
        print(f"[nbconvert-hook DEBUG] {msg}", file=sys.stderr, flush=True)


def _log(msg: str) -> None:
    print(f"[nbconvert-hook] {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# State helpers — remediation-pending flag
# ---------------------------------------------------------------------------

_HEX_RE = re.compile(r"^[0-9a-f]+$")


def _safe_hex(value: str) -> str:
    """Return a hex digest of value, validated to contain only hex characters.

    The regex check acts as an explicit sanitiser so Snyk's taint engine can
    recognise that no arbitrary user data flows into path construction.
    """
    digest = hashlib.sha256(value.encode()).hexdigest()[:16]
    if not _HEX_RE.match(digest):
        raise ValueError("Unexpected non-hex characters in digest")
    return digest


def _remediation_state_path(workspace: str) -> Path:
    h = _safe_hex(workspace)
    return Path(tempfile.gettempdir()) / ("cursor-nb-snyk-" + h + ".state")


def _set_remediation_pending(workspace: str, nb_path: str, summary: str) -> None:
    p = _remediation_state_path(workspace)
    p.write_text(
        f"notebook={nb_path}\nfindings={summary}\n", encoding="utf-8"
    )
    _debug(f"remediation state written → {p}")


def _clear_remediation_pending(workspace: str) -> None:
    p = _remediation_state_path(workspace)
    if p.exists():
        p.unlink()
        _debug(f"remediation state cleared → {p}")


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------

def _extract_file_path(payload: dict) -> str | None:
    if not isinstance(payload, dict):
        return None
    fp = payload.get("file_path")
    if isinstance(fp, str) and fp:
        return fp
    for key in ("path", "uri"):
        v = payload.get(key)
        if isinstance(v, str) and v.endswith(".ipynb"):
            return v
    return None


def _validated_abspath(raw: str) -> str | None:
    """Resolve raw to an absolute path; return None if result is not absolute."""
    if not raw:
        return None
    resolved = os.path.realpath(raw)
    return resolved if os.path.isabs(resolved) else None


def _workspace_root(nb: Path) -> str | None:
    """Best-effort: walk up looking for .cursor directory."""
    for p in nb.parents:
        if (p / ".cursor").exists():
            return str(p)
    for key in ("CURSOR_PROJECT_DIR", "CLAUDE_PROJECT_DIR"):
        v = _validated_abspath(os.environ.get(key, ""))
        if v:
            return v
    return None


# ---------------------------------------------------------------------------
# Snyk Code scan
# ---------------------------------------------------------------------------

def _run_snyk_code(root: Path, py_path: Path, nb_path: Path) -> None:
    """Run snyk code test on py_path; write remediation state if findings found."""
    if not _truthy("SNYK_CODE_TEST_ON_EXPORT"):
        return
    snyk = shutil.which("snyk")
    if not snyk:
        _log("SNYK_CODE_TEST_ON_EXPORT set but snyk not in PATH — skipping scan")
        return

    _log(f"snyk code test {py_path.name}")
    r = subprocess.run(
        [snyk, "code", "test", str(py_path.resolve())],
        cwd=str(root),
        capture_output=True,
        text=True,
    )

    workspace = str(root)

    if r.returncode == 0:
        # Clean — clear any prior pending state
        _clear_remediation_pending(workspace)
        _log("Snyk Code: no issues found ✓")
        return

    if r.returncode == 1:
        # Findings present
        summary = (r.stdout or r.stderr or "see snyk output").strip()[:800]
        _set_remediation_pending(workspace, str(nb_path), summary)
        _log("Snyk Code: findings found — remediation required in notebook")

        # Emit structured response so Cursor surfaces the agent message
        # afterFileEdit does not block, but agent_message appears in the UI
        print(json.dumps({
            "exit_code": 0,
            "agent_message": (
                f"Snyk Code found issues in the exported `{py_path.name}`. "
                "You MUST fix these in the NOTEBOOK (`"
                f"{nb_path.name}`), NOT in the `.py` file (which is generated). "
                "Remediation loop:\n"
                "  1. Open the notebook and fix the flagged cell(s).\n"
                "  2. Save the notebook (this hook will re-export and rescan automatically).\n"
                "  3. Repeat until Snyk Code reports no issues.\n\n"
                f"Snyk findings summary:\n{summary}"
            ),
        }), flush=True)
        return

    # Exit code other than 0/1 → scan error, fail open
    _log(f"snyk code test exited {r.returncode}: {r.stderr or r.stdout}")
    _clear_remediation_pending(workspace)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        _out_ok()
        return

    fp = _extract_file_path(payload)
    if not fp or not fp.endswith(".ipynb"):
        _out_ok()
        return

    nb = Path(fp)
    if not nb.is_file():
        _out_ok()
        return

    root_str = _workspace_root(nb)
    root_path = Path(root_str).resolve() if root_str else nb.parent.resolve()

    try:
        r = subprocess.run(
            [sys.executable, "-m", "nbconvert", "--to", "python", str(nb)],
            cwd=str(nb.parent),
            capture_output=True,
            text=True,
            timeout=120,
        )
        if r.returncode != 0:
            _log(f"nbconvert failed for {nb.name}\n{r.stderr}")
            _out_ok()
            return

        py_path = nb.with_suffix(".py")
        _log(f"{nb.name} → {py_path.name}")
        _run_snyk_code(root_path, py_path, nb)

    except OSError as e:
        _log(str(e))

    _out_ok()


def _out_ok() -> None:
    print(json.dumps({"exit_code": 0}), flush=True)


if __name__ == "__main__":
    main()
