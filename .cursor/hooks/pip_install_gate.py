#!/usr/bin/env python3
"""
Cursor Hook: Snyk Package Health Gate for pip installs in Jupyter notebooks.

WORKFLOW
--------
When a pip install command is detected (beforeShellExecution), the hook runs
two autonomous checks in order — no human-in-the-loop voucher step required:

  1. PyPI release-age check — queries pypi.org for the package's publish date.
     Blocks any package whose latest (or pinned) version was released within
     the last 24 hours (configurable via SNYK_PIP_GATE_MAX_AGE_HOURS).
     This catches typosquatting and dependency-confusion packages immediately.

  2. Snyk open-source vulnerability check — runs ``snyk test`` on a temporary
     requirements file. Blocks if Snyk reports known vulnerabilities (exit 1).

Only when both checks pass is the install allowed.

Enable the gate by creating the flag file:
  .cursor/enable-snyk-pip-gate   (empty file)

Without that flag the hook exits 0 / allow for all events (fail-open).

HOOKS.JSON wiring:
  "beforeShellExecution" → python3 .cursor/hooks/pip_install_gate.py
  "stop"                 → python3 .cursor/hooks/pip_install_gate.py

Set CURSOR_HOOK_DEBUG=1 for verbose stderr output.
Set SNYK_PIP_GATE_MAX_AGE_HOURS to override the 24-hour recency threshold.
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
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEBUG = os.environ.get("CURSOR_HOOK_DEBUG", "0") == "1"

# pip patterns that trigger the gate
_PIP_RE = re.compile(
    r"^(?:python3?|py)\s+-m\s+pip\s+install\b|^pip3?\s+install\b|"
    r"^%pip\s+install\b|^!pip3?\s+install\b",
    re.I,
)

# Strips version specifiers and extras so we can extract the bare package name
_PKG_NAME_STRIP_RE = re.compile(r"[=<>!~\[\]@;].*$")

_HEX_RE = re.compile(r"^[0-9a-f]+$")


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Workspace helpers
# ---------------------------------------------------------------------------

def _validated_abspath(raw: str) -> str | None:
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


def _safe_hex(value: str) -> str:
    digest = hashlib.sha256(value.encode()).hexdigest()[:16]
    if not _HEX_RE.match(digest):
        raise ValueError("Unexpected non-hex characters in digest")
    return digest


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
    """Return package specs from a pip install command, or None for complex invocations."""
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


def _strip_pkg_name(spec: str) -> str:
    """Extract bare package name from a spec like 'numpy>=1.0' or 'pandas[excel]'."""
    return _PKG_NAME_STRIP_RE.sub("", spec).strip()


# ---------------------------------------------------------------------------
# PyPI release-age check
# ---------------------------------------------------------------------------

def _pypi_release_age_hours(spec: str) -> float | None:
    """
    Query PyPI for the latest (or pinned) version of a package and return how
    many hours ago it was first published. Returns None on any error (fail-open).
    """
    pkg_name = _strip_pkg_name(spec)
    if not pkg_name:
        return None

    pinned: str | None = None
    pin_m = re.search(r"==\s*([^\s,;]+)", spec)
    if pin_m:
        pinned = pin_m.group(1).strip()

    url = f"https://pypi.org/pypi/{urllib.parse.quote(pkg_name, safe='')}/json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "snyk-pip-gate/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return None

    version = pinned or (data.get("info") or {}).get("version")
    if not version:
        return None

    releases = (data.get("releases") or {}).get(version, [])
    if not releases:
        return None

    upload_times: list[str] = []
    for r in releases:
        t = r.get("upload_time_iso_8601") or r.get("upload_time")
        if t:
            upload_times.append(t)
    if not upload_times:
        return None

    earliest = min(upload_times)
    try:
        normalized = earliest.replace("Z", "+00:00")
        if "+" not in normalized and "-" not in normalized[10:]:
            normalized += "+00:00"
        dt = datetime.fromisoformat(normalized)
        return (datetime.now(timezone.utc) - dt).total_seconds() / 3600.0
    except (ValueError, OverflowError):
        return None


# ---------------------------------------------------------------------------
# Snyk open-source vulnerability check
# ---------------------------------------------------------------------------

def _snyk_test_packages(packages: list[str], workspace: str) -> tuple[bool, str]:
    """
    Run ``snyk test`` against a temporary requirements file.
    Returns (passed, failure_reason). Fails open if snyk is unavailable.
    """
    snyk = shutil.which("snyk")
    if not snyk:
        _log("snyk not in PATH — skipping open-source vulnerability check")
        return True, ""

    snyk_timeout = int(os.environ.get("SNYK_PIP_GATE_SNYK_TIMEOUT", "120"))
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix="-req.txt", delete=False, encoding="utf-8"
        ) as f:
            for pkg in packages:
                f.write(pkg.strip() + "\n")
            tmp_path = f.name

        r = subprocess.run(
            [snyk, "test", f"--file={tmp_path}", "--package-manager=pip",
             f"--command={sys.executable}"],
            cwd=workspace,
            capture_output=True,
            text=True,
            timeout=snyk_timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"Snyk test timed out after {snyk_timeout}s."
    except OSError as e:
        _log(f"snyk test could not run: {e}")
        return True, ""  # fail-open
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    if r.returncode == 0:
        return True, ""

    tail = ((r.stderr or "") + (r.stdout or ""))[-1500:]
    return False, f"Snyk found vulnerabilities (exit {r.returncode}):\n{tail}"


# ---------------------------------------------------------------------------
# Hook handlers
# ---------------------------------------------------------------------------

def _handle_before_shell(data: dict, workspace: str) -> None:
    command = data.get("command", "")
    if not _is_pip_install(command):
        _allow()
        return

    if not _gate_enabled(workspace):
        _allow()
        return

    packages = _parse_packages(command)
    if packages is None:
        # Complex invocation (requirements file, VCS URL, editable) — skip gate
        _allow()
        return

    max_age_hours = float(os.environ.get("SNYK_PIP_GATE_MAX_AGE_HOURS", "24"))

    # 1. PyPI release-age check
    too_new: list[str] = []
    for spec in packages:
        age = _pypi_release_age_hours(spec)
        _debug(f"{spec}: age={age}")
        if age is not None and age < max_age_hours:
            pkg_name = _strip_pkg_name(spec)
            too_new.append(f"{pkg_name} (released {age:.1f}h ago)")

    if too_new:
        summary = "\n".join(f"  • {p}" for p in too_new)
        msg = (
            f"Install blocked: {len(too_new)} package(s) released within the last "
            f"{max_age_hours:.0f} hours — possible typosquatting or dependency confusion.\n{summary}"
        )
        _log(f"INSTALL BLOCKED — too-new packages: {too_new}")
        _deny(
            msg,
            (
                f"INSTALL BLOCKED: the following package(s) were published within the last "
                f"{max_age_hours:.0f} hours and cannot be installed until they have a longer "
                f"publication history:\n{summary}\n"
                "Wait for the recency window to pass, use a pinned older version, or set "
                "SNYK_PIP_GATE_MAX_AGE_HOURS to adjust the threshold."
            ),
        )
        return

    # 2. Snyk open-source vulnerability check
    passed, reason = _snyk_test_packages(packages, workspace)
    if not passed:
        _log(f"INSTALL BLOCKED — Snyk found vulnerabilities in {packages}")
        _deny(
            f"Install blocked: Snyk found known vulnerabilities in the requested packages.\n{reason}",
            (
                f"INSTALL BLOCKED: Snyk reported vulnerabilities for {packages!r}.\n{reason}\n"
                "Fix the version constraints to avoid vulnerable releases, then retry."
            ),
        )
        return

    _log(f"pip install allowed — all checks passed for {packages}")
    _allow()


def _handle_stop(data: dict, workspace: str) -> None:
    _out({})


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
    elif event == "stop":
        _handle_stop(data, workspace)
    else:
        _out({"exit_code": 0})


if __name__ == "__main__":
    main()
