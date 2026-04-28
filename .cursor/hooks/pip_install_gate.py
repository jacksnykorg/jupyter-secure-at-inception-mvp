#!/usr/bin/env python3
"""
Cursor Hook: Snyk Package Health Gate for pip installs in Jupyter notebooks.

WORKFLOW
--------
1. Agent proposes a pip install command (in notebook or shell).
   → beforeShellExecution: BLOCKS the install, tells agent to run
     snyk_package_health_check first and records a pending-state file.
2. Agent runs snyk_package_health_check (MCP).
   → beforeMCPExecution: detects the scan tool, clears the pending state.
3. Install is retried → a one-shot **voucher** file allows that install; the next
   pip install again requires a fresh health check.
4. Session ends with unscanned pending state → stop: emits followup reminder.

Enable the gate by creating the flag file:
  .cursor/enable-snyk-pip-gate   (empty file)

Without that flag the hook exits 0 / allow for all events (fail-open).

HOOKS.JSON wiring (all four events must point here):
  "afterFileEdit"        → not used by this gate; leave for nbconvert hook
  "beforeShellExecution" → python3 .cursor/hooks/pip_install_gate.py
  "beforeMCPExecution"   → python3 .cursor/hooks/pip_install_gate.py
  "stop"                 → python3 .cursor/hooks/pip_install_gate.py

State and voucher files live under `tempfile.gettempdir()`, keyed by a hash of
the workspace path.
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
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEBUG = os.environ.get("CURSOR_HOOK_DEBUG", "0") == "1"



# MCP tool name that satisfies the gate
HEALTH_CHECK_TOOL = "snyk_package_health_check"

# pip patterns that trigger the gate
_PIP_RE = re.compile(
    r"^(?:python3?|py)\s+-m\s+pip\s+install\b|^pip3?\s+install\b|"
    r"^%pip\s+install\b|^!pip3?\s+install\b",
    re.I,
)


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _debug(msg: str) -> None:
    if DEBUG:
        print(f"[pip-gate DEBUG] {msg}", file=sys.stderr, flush=True)


def _log(msg: str) -> None:
    print(f"[pip-gate] {msg}", file=sys.stderr, flush=True)


def _out(payload: dict) -> None:
    print(json.dumps(payload), flush=True)


def _allow() -> None:
    _out({"permission": "allow", "continue": True})


def _deny(user_msg: str, agent_msg: str) -> None:
    _out({
        "permission": "deny",
        "user_message": user_msg,
        "agent_message": agent_msg,
    })
    sys.exit(2)


def _ask(user_msg: str, agent_msg: str) -> None:
    _out({
        "permission": "ask",
        "continue": True,
        "user_message": user_msg,
        "agent_message": agent_msg,
    })


# ---------------------------------------------------------------------------
# State file helpers (workspace-scoped)
# ---------------------------------------------------------------------------

def _validated_abspath(raw: str) -> str | None:
    """Resolve raw to an absolute path; return None if result is not absolute."""
    if not raw:
        return None
    resolved = os.path.realpath(raw)
    return resolved if os.path.isabs(resolved) else None


def _workspace(data: dict) -> str:
    roots = data.get("workspace_roots") or []
    if roots:
        v = _validated_abspath(str(roots[0]))
        if v:
            return v
    for key in ("file_path", "path"):
        fp = data.get(key, "")
        if fp:
            for p in Path(fp).parents:
                if (p / ".cursor").exists():
                    return str(p)
    for env_key in ("CURSOR_PROJECT_DIR", "CLAUDE_PROJECT_DIR"):
        v = _validated_abspath(os.environ.get(env_key, ""))
        if v:
            return v
    return os.getcwd()


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


def _state_path(workspace: str) -> Path:
    h = _safe_hex(workspace)
    return Path(tempfile.gettempdir()) / ("cursor-pip-gate-" + h + ".state")


def _pending(workspace: str) -> bool:
    return _state_path(workspace).exists()


def _read_state(workspace: str) -> str:
    p = _state_path(workspace)
    return p.read_text(encoding="utf-8").strip() if p.exists() else ""


def _write_state(workspace: str, line: str) -> None:
    with _state_path(workspace).open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    _debug(f"wrote state → {_state_path(workspace)}")


def _clear_state(workspace: str) -> None:
    p = _state_path(workspace)
    if p.exists():
        p.unlink()
        _debug(f"cleared state → {p}")


def _voucher_path(workspace: str) -> Path:
    h = _safe_hex(workspace)
    return Path(tempfile.gettempdir()) / ("cursor-pip-gate-" + h + ".voucher")


def _has_voucher(workspace: str) -> bool:
    return _voucher_path(workspace).is_file()


def _consume_voucher(workspace: str) -> None:
    p = _voucher_path(workspace)
    if p.exists():
        p.unlink()
        _debug(f"consumed voucher → {p}")


def _grant_voucher(workspace: str) -> None:
    _voucher_path(workspace).touch()
    _debug(f"granted voucher → {_voucher_path(workspace)}")


# ---------------------------------------------------------------------------
# Gate flag check
# ---------------------------------------------------------------------------

def _gate_enabled(workspace: str) -> bool:
    flag = os.path.join(workspace, ".cursor", "enable-snyk-pip-gate")
    return os.path.isfile(flag)


# ---------------------------------------------------------------------------
# pip command helpers
# ---------------------------------------------------------------------------

def _is_pip_install(command: str) -> bool:
    return bool(_PIP_RE.match(command.strip()))


def _parse_packages(command: str) -> list[str] | None:
    """Return simple package specs from a pip install command, or None to skip gate."""
    s = command.strip()
    m = re.match(
        r"^(?:(?:python3?|py)\s+-m\s+pip|pip3?|%pip|!pip3?)\s+install\s+(.*)",
        s, re.I | re.S,
    )
    if not m:
        return None
    rest = m.group(1).strip()
    if not rest:
        return None

    # Tokenise respecting basic quoting
    parts: list[str] = []
    cur: list[str] = []
    in_q: str | None = None
    for ch in rest:
        if in_q:
            cur.append(ch)
            if ch == in_q:
                in_q = None
            continue
        if ch in "\"'":
            in_q = ch
            cur.append(ch)
            continue
        if ch.isspace() and cur:
            parts.append("".join(cur))
            cur = []
        elif not ch.isspace():
            cur.append(ch)
    if cur:
        parts.append("".join(cur))

    reqs: list[str] = []
    i = 0
    while i < len(parts):
        t = parts[i]
        if t.startswith("-"):
            if t in ("-r", "--requirement", "-e", "--editable"):
                return None  # complex invocation — skip gate
            if t in ("-c", "--constraint", "-f", "--find-links") and i + 1 < len(parts):
                i += 2
                continue
            i += 1
            continue
        if "://" in t or t.startswith("git+"):
            return None
        reqs.append(t)
        i += 1
    return reqs if reqs else None


# ---------------------------------------------------------------------------
# Hook handlers
# ---------------------------------------------------------------------------

def _handle_before_shell(data: dict, workspace: str) -> None:
    command = data.get("command", "")
    if not _is_pip_install(command):
        _allow()
        return

    if not _gate_enabled(workspace):
        # Gate disabled — fall back to optional snyk test (legacy behaviour)
        _legacy_snyk_test(command, workspace)
        return

    # One-shot allow after snyk_package_health_check cleared the pending state.
    if _has_voucher(workspace):
        _consume_voucher(workspace)
        _log("pip install allowed (health-check voucher consumed)")
        _allow()
        return

    if _pending(workspace):
        # Already blocked from a previous command; keep blocking
        changes = _read_state(workspace)
        _log("INSTALL BLOCKED — snyk_package_health_check not yet run")
        _deny(
            "Install blocked: run snyk_package_health_check for each package first.",
            (
                "INSTALL BLOCKED: packages were proposed for install but "
                "snyk_package_health_check has not been called yet for this session. "
                f"Pending packages:\n{changes}\n"
                "Call snyk_package_health_check (ecosystem='pypi', package_name=...) "
                "for each package, then retry the install."
            ),
        )
        return

    # Record the install attempt as pending
    packages = _parse_packages(command) or [command]
    ts = datetime.now().isoformat(timespec="seconds")
    for pkg in packages:
        _write_state(workspace, f"{ts}: {pkg}")

    _log("INSTALL BLOCKED — snyk_package_health_check required before install")
    _deny(
        "Install blocked: run snyk_package_health_check for each package first, then retry.",
        (
            f"INSTALL BLOCKED: you attempted to install {packages!r} without first "
            "running snyk_package_health_check. You MUST call "
            "snyk_package_health_check (ecosystem='pypi', package_name=<pkg>) for "
            "each package before any pip/pip3/%pip/!pip install. "
            "After all health checks pass, retry the install."
        ),
    )


def _legacy_snyk_test(command: str, workspace: str) -> None:
    """Fallback: run snyk test via CLI when gate flag is absent (original behaviour)."""
    reqs = _parse_packages(command)
    if not reqs:
        _allow()
        return

    snyk = shutil.which("snyk")
    if not snyk:
        _log("snyk not in PATH — install CLI or remove .cursor/enable-snyk-pip-gate")
        _allow()
        return

    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix="-req.txt", delete=False, encoding="utf-8"
        ) as f:
            for line in reqs:
                f.write(line.strip() + "\n")
            tmp_path = f.name

        r = subprocess.run(
            [snyk, "test", f"--file={tmp_path}", f"--command={sys.executable}"],
            cwd=workspace,
            capture_output=True,
            text=True,
        )
    except OSError as e:
        _log(f"snyk test failed: {e}")
        _allow()
        return
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    if r.returncode == 0:
        _allow()
    elif r.returncode == 1:
        _ask(
            "Snyk reported dependency issues. Review and approve to continue.",
            "Snyk `test` found issues. Confirm with the user or fix versions, then retry.",
        )
    else:
        _log(f"snyk test error: {r.stderr or r.stdout}")
        _allow()


def _handle_before_mcp(data: dict, workspace: str) -> None:
    tool_name = data.get("tool_name", "")
    if HEALTH_CHECK_TOOL in tool_name.lower() and _pending(workspace):
        changes = _read_state(workspace)
        _clear_state(workspace)
        _grant_voucher(workspace)
        _log(f"snyk_package_health_check called — pip gate cleared. Was pending:\n{changes}")
    _out({"exit_code": 0})


def _handle_stop(data: dict, workspace: str) -> None:
    if not _pending(workspace):
        _out({})
        return
    changes = _read_state(workspace)
    _clear_state(workspace)
    _consume_voucher(workspace)
    _log("SESSION ENDED with unvetted pip installs pending (state cleared for next session)")
    _out({
        "followup_message": (
            "Notebook / pip workflow: a `pip install` (or `%pip` / `!pip`) was blocked because "
            "`snyk_package_health_check` had not been run yet for the listed package(s). "
            "Pending lines from this session:\n"
            f"{changes}\n\n"
            "Next time: run **`snyk_package_health_check`** with `ecosystem: \"pypi\"` (and "
            "`package_name` per package), then retry install. "
            "The hook has **cleared** this pending state—your next session starts clean unless "
            "another blocked install runs."
        )
    })


# ---------------------------------------------------------------------------
# Main dispatch
# ---------------------------------------------------------------------------

def main() -> None:
    try:
        raw = sys.stdin.read()
        data: dict = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as exc:
        _log(f"JSON parse error: {exc}")
        _out({"exit_code": 0})
        return

    event = data.get("hook_event_name", "")
    workspace = _workspace(data)
    _debug(f"event={event!r} workspace={workspace!r}")

    if event == "beforeShellExecution":
        _handle_before_shell(data, workspace)
    elif event == "beforeMCPExecution":
        _handle_before_mcp(data, workspace)
    elif event == "stop":
        _handle_stop(data, workspace)
    else:
        # afterFileEdit or unknown — no-op
        _out({"exit_code": 0})


if __name__ == "__main__":
    main()
