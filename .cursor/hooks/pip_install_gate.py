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
     When a package is too new, the hook also finds the newest non-yanked
     version older than the threshold and includes a ``pip install pkg==X.Y.Z``
     retry command in the deny message so the agent can immediately switch to
     the safe version without human intervention.

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
            if t in ("-e", "--editable"):
                return None
            if t in ("-r", "--requirement"):
                return None  # signal: caller must handle requirements file
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


def _reqs_file_path_from_command(command: str, workspace: str) -> "Path | None":
    """If the command has -r <file>, return the resolved Path if the file exists."""
    m = re.search(r"(?:-r|--requirement)\s+([^\s]+)", command, re.I)
    if not m:
        return None
    raw = m.group(1).strip().strip("'\"")
    p = Path(raw) if Path(raw).is_absolute() else Path(workspace) / raw
    resolved = p.resolve()
    return resolved if resolved.is_file() else None


def _parse_reqs_file(path: "Path") -> list[str]:
    """Parse a requirements.txt into package specs, skipping flags, VCS URLs, and comments."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    packages: list[str] = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-") or line.startswith("--"):
            continue
        if "://" in line or line.startswith("git+"):
            continue
        line = re.split(r"\s+#", line)[0].strip()
        if line:
            packages.append(line)
    return packages


def _extract_pip_from_cell_source(tool_input: dict) -> list[str]:
    """
    Return pip install lines found in structured cell-source args
    (NotebookEdit-style tools where the cell source is a named key).
    Scans fields directly so leading-whitespace anchors work.
    """
    cell_source_keys = ("new_source", "source", "cell_source", "text", "code", "src")
    commands: list[str] = []
    for key in cell_source_keys:
        val = tool_input.get(key)
        if not isinstance(val, str):
            continue
        for line in val.splitlines():
            stripped = line.strip()
            if stripped and _PIP_RE.search(stripped):
                commands.append(stripped)
    return commands


def _pip_installs_from_notebook_json(text: str) -> list[str]:
    """
    Parse a string as notebook JSON and return pip install lines found in any
    code cell's source. Used for Cursor's beforeFileEdit payload which delivers
    the full notebook JSON in new_content. Falls back to a permissive text scan.
    """
    commands: list[str] = []
    try:
        nb = json.loads(text)
        for cell in nb.get("cells") or []:
            if cell.get("cell_type") != "code":
                continue
            src = cell.get("source") or ""
            if isinstance(src, list):
                src = "".join(src)
            for line in src.splitlines():
                stripped = line.strip()
                if stripped and _PIP_RE.search(stripped):
                    commands.append(stripped)
    except (json.JSONDecodeError, AttributeError):
        _pip_bare = re.compile(
            r"""(?:^|[^a-zA-Z0-9_])(%pip|!pip3?|pip3?)\s+install\b(.+)""", re.I | re.M
        )
        for m in _pip_bare.finditer(text):
            commands.append(f"{m.group(1)} install {m.group(2).split(chr(10))[0].strip()}")
    return commands


def _strip_pkg_name(spec: str) -> str:
    """Extract bare package name from a spec like 'numpy>=1.0' or 'pandas[excel]'."""
    return _PKG_NAME_STRIP_RE.sub("", spec).strip()


# ---------------------------------------------------------------------------
# PyPI release-age check
# ---------------------------------------------------------------------------

def _pypi_check(spec: str, max_age_hours: float) -> tuple[float | None, str | None]:
    """
    Single PyPI API call that returns (age_hours, safe_version).

    age_hours: hours since the target version was first uploaded. None on error.
    safe_version: the newest non-yanked version older than max_age_hours that the
                  agent can pin instead, or None if no such version exists or the
                  package is not too new.
    """
    pkg_name = _strip_pkg_name(spec)
    if not pkg_name:
        return None, None

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
        return None, None

    now = datetime.now(timezone.utc)

    def _parse_dt(t: str) -> datetime | None:
        try:
            normalized = t.replace("Z", "+00:00")
            if "+" not in normalized and "-" not in normalized[10:]:
                normalized += "+00:00"
            return datetime.fromisoformat(normalized)
        except (ValueError, OverflowError):
            return None

    def _earliest_upload(files: list) -> datetime | None:
        times = [_parse_dt(f.get("upload_time_iso_8601") or f.get("upload_time") or "") for f in files]
        valid = [t for t in times if t is not None]
        return min(valid) if valid else None

    all_releases: dict = data.get("releases") or {}
    target_ver = pinned or (data.get("info") or {}).get("version")
    if not target_ver:
        return None, None

    target_dt = _earliest_upload(all_releases.get(target_ver, []))
    if target_dt is None:
        return None, None

    target_age = (now - target_dt).total_seconds() / 3600.0

    if target_age >= max_age_hours:
        return target_age, None

    # Find the newest non-yanked version that is old enough
    safe_candidates: list[tuple[str, datetime]] = []
    for ver, files in all_releases.items():
        if not files or any(f.get("yanked") for f in files):
            continue
        dt = _earliest_upload(files)
        if dt is not None and (now - dt).total_seconds() / 3600.0 >= max_age_hours:
            safe_candidates.append((ver, dt))

    if not safe_candidates:
        return target_age, None

    safe_candidates.sort(key=lambda x: x[1], reverse=True)
    return target_age, safe_candidates[0][0]


# ---------------------------------------------------------------------------
# OSV advisory check (pre-install, no local env needed)
# ---------------------------------------------------------------------------

def _osv_check_packages(packages: list[str]) -> tuple[bool, str]:
    """
    Query OSV.dev for known vulnerabilities by package name+version.
    Returns (passed, failure_reason).  Fails open if the API is unreachable.
    """
    import urllib.request as _ureq
    OSV_URL = "https://api.osv.dev/v1/querybatch"
    queries = []
    specs = []
    for spec in packages:
        name = _strip_pkg_name(spec)
        ver_match = re.search(r"==([^\s,;]+)", spec)
        version = ver_match.group(1) if ver_match else None
        # OSV without a pinned version returns all historical CVEs — not actionable.
        # Only check exact pinned versions.
        if not version:
            continue
        queries.append({"package": {"name": name, "ecosystem": "PyPI"}, "version": version})
        specs.append(spec)

    if not queries:
        return True, ""

    try:
        body = json.dumps({"queries": queries}).encode()
        req = _ureq.Request(
            OSV_URL,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "snyk-pip-gate/1.0"},
            method="POST",
        )
        with _ureq.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        return True, ""  # fail-open if OSV unreachable

    findings: list[str] = []
    for spec, result in zip(specs, data.get("results", [])):
        vulns = result.get("vulns", [])
        if not vulns:
            continue
        name = _strip_pkg_name(spec)
        ids = ", ".join(
            next((a for a in v.get("aliases", []) if a.startswith("CVE-")), v["id"])
            for v in vulns[:4]
        )
        extra = f" (+{len(vulns)-4} more)" if len(vulns) > 4 else ""
        sev_counts: dict[str, int] = {}
        for v in vulns:
            s = v.get("database_specific", {}).get("severity", "UNKNOWN")
            sev_counts[s] = sev_counts.get(s, 0) + 1
        sev_str = ", ".join(f"{c}×{s}" for s, c in sorted(sev_counts.items()))
        findings.append(f"  • {name}: {ids}{extra} [{sev_str}]")

    if findings:
        return False, "OSV advisory database found vulnerabilities:\n" + "\n".join(findings)
    return True, ""


# ---------------------------------------------------------------------------
# Snyk open-source vulnerability check (supplementary)
# ---------------------------------------------------------------------------

def _pypi_latest_version(pkg_name: str) -> "str | None":
    """Return the latest non-yanked stable version of a package from PyPI."""
    try:
        url = f"https://pypi.org/pypi/{urllib.parse.quote(pkg_name)}/json"
        req = urllib.request.Request(url, headers={"User-Agent": "snyk-pip-gate/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        releases = data.get("releases", {})
        candidates = []
        for ver, files in releases.items():
            if not files or all(f.get("yanked") for f in files):
                continue
            try:
                parts = [int(x) for x in ver.split(".")[:3]]
                candidates.append((parts, ver))
            except ValueError:
                pass
        if not candidates:
            return None
        candidates.sort(reverse=True)
        return candidates[0][1]
    except Exception:
        return None


def _snyk_test_packages(packages: list[str], workspace: str) -> tuple[bool, str]:
    """
    Run ``snyk test --json`` against a temp requirements file.
    Parses JSON to report only security vulns (not license issues).
    - exit 0  → allow
    - exit 1  → hard block with SNYK-PYTHON-xxx IDs
    - exit 2  → Snyk can't verify (pip resolution failure) → hard block, suggest latest stable
    """
    snyk = shutil.which("snyk")
    if not snyk:
        _log("snyk not in PATH — blocking install (cannot verify package safety)")
        return False, "Snyk CLI not found on PATH — cannot verify package safety."

    venv_python = Path(workspace) / ".venv" / "bin" / "python3"
    python_cmd = str(venv_python) if venv_python.exists() else sys.executable

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
             f"--command={python_cmd}", "--json"],
            cwd=workspace,
            capture_output=True,
            text=True,
            timeout=snyk_timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"Snyk test timed out after {snyk_timeout}s."
    except OSError as e:
        return False, f"Snyk could not run: {e}"
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    if r.returncode == 0:
        return True, ""

    if r.returncode != 1:
        suggestions = []
        for spec in packages:
            name = _strip_pkg_name(spec)
            latest = _pypi_latest_version(name)
            if latest:
                suggestions.append(f"pip install {name}=={latest}")
        hint = ("\nTry the latest stable version instead:\n  " + "\n  ".join(suggestions)
                if suggestions else "")
        return False, f"Snyk could not verify this package (dependency resolution failed).{hint}"

    try:
        data = json.loads(r.stdout)
        vulns = [v for v in data.get("vulnerabilities", [])
                 if v.get("type") != "license"]
        if not vulns:
            return True, ""
        lines: list[str] = []
        seen: set[str] = set()
        for v in vulns:
            vid = v.get("id", "")
            if vid in seen:
                continue
            seen.add(vid)
            sev = v.get("severity", "").upper()
            title = v.get("title", "vulnerability")
            pkg = v.get("packageName", "")
            lines.append(f"  • [{sev}] {vid} in {pkg}: {title}")
        return False, "Snyk found security vulnerabilities:\n" + "\n".join(lines[:10])
    except Exception:
        tail = (r.stdout or r.stderr or "")[-1000:]
        return False, f"Snyk found vulnerabilities:\n{tail}"


# ---------------------------------------------------------------------------
# Shared gate logic
# ---------------------------------------------------------------------------

def _run_pip_gate_checks(packages: list[str], workspace: str, context: str = "pip install") -> bool:
    """
    Age + Snyk checks for a resolved package list.
    Returns True if the install should be allowed; calls _deny() and returns False if blocked.
    """
    max_age_hours = float(os.environ.get("SNYK_PIP_GATE_MAX_AGE_HOURS", "24"))

    too_new: list[tuple[str, float, "str | None"]] = []
    for spec in packages:
        age, safe_ver = _pypi_check(spec, max_age_hours)
        _debug(f"{spec}: age={age} safe_ver={safe_ver}")
        if age is not None and age < max_age_hours:
            too_new.append((_strip_pkg_name(spec), age, safe_ver))

    if too_new:
        lines: list[str] = []
        retry_specs: list[str] = []
        for pkg_name, age, safe_ver in too_new:
            line = f"  • {pkg_name} (released {age:.1f}h ago)"
            if safe_ver:
                line += f" — pin to =={safe_ver} instead"
                retry_specs.append(f"{pkg_name}=={safe_ver}")
            else:
                line += " — no safe version available yet"
            lines.append(line)

        summary = "\n".join(lines)
        retry_hint = (
            f"Retry with: pip install {' '.join(retry_specs)}"
            if retry_specs
            else f"Wait until the package(s) are at least {max_age_hours:.0f} hours old."
        )
        _log(f"BLOCKED ({context}) — too-new: {[t[0] for t in too_new]}")
        _deny(
            f"{context} blocked: package(s) released within the last {max_age_hours:.0f} hours.\n"
            f"{summary}\n{retry_hint}",
            f"INSTALL BLOCKED ({context}): packages published within {max_age_hours:.0f}h:\n"
            f"{summary}\n{retry_hint}\nSet SNYK_PIP_GATE_MAX_AGE_HOURS to adjust.",
        )
        return False

    # Snyk vulnerability check — real SNYK-PYTHON-xxx IDs via snyk auth.
    # exit 2 (can't resolve) is also a hard block; suggests latest stable version.
    passed, reason = _snyk_test_packages(packages, workspace)
    if not passed:
        _log(f"BLOCKED ({context}) — Snyk: {reason[:80]}")
        _deny(
            f"{context} blocked by Snyk: {reason}",
            f"INSTALL BLOCKED ({context}): {reason}\nFix the version constraints, then retry.",
        )
        return False

    _log(f"allowed ({context}) — all checks passed for {packages}")
    return True


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
        # Check for -r requirements.txt — read the file and gate its contents
        reqs_path = _reqs_file_path_from_command(command, workspace)
        if reqs_path is None:
            # Editable install or unresolvable path — skip gate
            _allow()
            return
        packages = _parse_reqs_file(reqs_path)
        if not packages:
            _allow()
            return
        if _run_pip_gate_checks(packages, workspace, context=f"pip install -r {reqs_path.name}"):
            _allow()
        return

    if _run_pip_gate_checks(packages, workspace):
        _allow()


def _handle_notebook_edit(data: dict, workspace: str) -> None:
    """
    Gate 3 — fires before a notebook file is written (beforeFileEdit on .ipynb).

    Cursor's beforeFileEdit payload delivers the full notebook JSON in new_content.
    This handler parses that JSON to find pip install lines in code cells, then
    runs the same age + Snyk checks as Gate 2.
    """
    if not _gate_enabled(workspace):
        _out({"exit_code": 0})
        return

    pip_cmds: list[str] = []

    # Path 1: structured cell source (e.g. a notebook-edit MCP tool)
    tool_input = data.get("tool_input") or data.get("toolArgs") or {}
    if isinstance(tool_input, dict):
        pip_cmds = _extract_pip_from_cell_source(tool_input)

    # Path 2: Cursor beforeFileEdit — full notebook JSON in new_content
    if not pip_cmds:
        for key in ("new_content", "content", "new_string"):
            body = data.get(key) or (tool_input.get(key) if isinstance(tool_input, dict) else None) or ""
            if body:
                pip_cmds = _pip_installs_from_notebook_json(body)
                if pip_cmds:
                    break

    if not pip_cmds:
        _out({"exit_code": 0})
        return

    for cmd in pip_cmds:
        normalised = re.sub(r"^[%!]", "", cmd).strip()
        pkgs = _parse_packages(normalised)
        if not pkgs:
            continue
        if not _run_pip_gate_checks(pkgs, workspace, context="Notebook cell pip install"):
            return  # _deny already called

    _out({"exit_code": 0})


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
    elif event in ("beforeFileEdit", "beforeNotebookEdit"):
        _handle_notebook_edit(data, workspace)
    elif event == "stop":
        _handle_stop(data, workspace)
    else:
        _out({"exit_code": 0})


if __name__ == "__main__":
    main()
