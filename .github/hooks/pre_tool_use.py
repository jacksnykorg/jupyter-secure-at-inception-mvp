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
  Before any pip install, the hook autonomously runs two checks in order:

    1. **PyPI release-age check** — queries pypi.org/pypi/<pkg>/json and blocks
       packages whose latest (or pinned) version was published within the last
       24 hours (configurable via SNYK_PIP_GATE_MAX_AGE_HOURS). This catches
       typosquatting and dependency-confusion packages before they can be installed.

    2. **Snyk open-source test** — runs ``snyk test`` on a temporary requirements
       file containing the requested packages. Blocks if Snyk reports known
       vulnerabilities (exit 1).

  No human-in-the-loop voucher step is needed; both checks run inline and the
  install is allowed only when both pass.

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
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
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

# Strips version specifiers and extras so we can extract the bare package name
_PKG_NAME_STRIP_RE = re.compile(r"[=<>!~\[\]@;].*$")


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
    Returns True if the tool call may proceed; False if denied.
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
# Gate 2 — pip install (autonomous: PyPI age + inline snyk test)
# ---------------------------------------------------------------------------


def _pip_gate_enabled(cwd: str) -> bool:
    return (Path(cwd) / ".cursor" / "enable-snyk-pip-gate").is_file()


def _parse_pip_packages(command: str) -> list[str] | None:
    """Return package specs from a pip install command, or None for complex invocations."""
    m = re.match(
        r"^(?:(?:python3?|py)\s+-m\s+pip|pip3?|%pip|!pip3?)\s+install\s+(.*)",
        command.strip(), re.I | re.S,
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


def _pypi_release_age_hours(spec: str) -> float | None:
    """
    Query PyPI for the latest (or pinned) version of a package and return how
    many hours ago it was first published. Returns None on any error (fail-open).
    """
    pkg_name = _strip_pkg_name(spec)
    if not pkg_name:
        return None

    # Extract pinned version if present, e.g. 'numpy==1.26.0' → '1.26.0'
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


def _snyk_test_packages(packages: list[str], cwd: str) -> tuple[bool, str]:
    """
    Run ``snyk test`` against a temporary requirements file.
    Returns (passed, failure_reason). Fails open if snyk is unavailable.
    """
    snyk = shutil.which("snyk")
    if not snyk:
        return True, ""

    snyk_timeout = int(os.environ.get("COPILOT_PRETOOL_SNYK_TIMEOUT", "300"))
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
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=snyk_timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"Snyk test timed out after {snyk_timeout}s."
    except OSError:
        return True, ""  # fail-open if snyk can't run
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    if r.returncode == 0:
        return True, ""

    tail = ((r.stderr or "") + (r.stdout or ""))[-1500:]
    return False, f"Snyk test found issues (exit {r.returncode}):\n{tail}"


def _check_pip_install(cwd: str, tool_name: str, tool_args: dict) -> None:
    """
    Gate 2 entry point — runs autonomously on every pip install.
    Order: PyPI age check first (fast, no subprocess), then Snyk (slower).
    Calls _deny() if either check fails; returns silently to allow the install.
    """
    if not _pip_gate_enabled(cwd):
        return

    command = _shell_command(tool_name, tool_args) or str(tool_args.get("command") or "")
    if not command or not _PIP_RE.search(command):
        return

    packages = _parse_pip_packages(command)
    if packages is None:
        # Complex invocation (requirements file, VCS URL, editable) — skip gate
        return

    max_age_hours = float(os.environ.get("SNYK_PIP_GATE_MAX_AGE_HOURS", "24"))

    # 1. PyPI release-age check — block packages too new to have been reviewed
    too_new: list[str] = []
    for spec in packages:
        age = _pypi_release_age_hours(spec)
        if age is not None and age < max_age_hours:
            pkg_name = _strip_pkg_name(spec)
            too_new.append(f"{pkg_name} (released {age:.1f}h ago)")

    if too_new:
        _deny(
            "pip install blocked: the following package(s) were released within the last "
            f"{max_age_hours:.0f} hours and may be malicious (typosquatting / dependency confusion):\n"
            + "\n".join(f"  • {p}" for p in too_new)
            + f"\nWait until the package has been published for at least "
            f"{max_age_hours:.0f} hours, or set SNYK_PIP_GATE_MAX_AGE_HOURS to override."
        )
        return

    # 2. Snyk open-source vulnerability check
    passed, reason = _snyk_test_packages(packages, cwd)
    if not passed:
        _deny(
            f"pip install blocked by Snyk: known vulnerabilities found in requested packages.\n{reason}"
        )


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

    if tool_name.lower() not in _SHELL_TOOLS:
        return

    _check_pip_install(cwd, tool_name, tool_args)


if __name__ == "__main__":
    main()
