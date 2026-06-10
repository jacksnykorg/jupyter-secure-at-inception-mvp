#!/usr/bin/env python3
"""
Copilot Hooks (preToolUse) — always-on security gates.

GATE 1 — Notebook execution gate (always enforced, non-negotiable order):
  When an agent tool call would execute a Jupyter notebook or run cells, this
  hook runs **before** that tool is allowed:

    1. Resolve the target ``.ipynb`` path from the tool payload (best-effort).
    2. **Export** — ``python -m nbconvert --to python <notebook.ipynb>`` (fresh
       export every time so the ``.py`` matches the notebook on disk).
    3. **Pip cell scan** — if .cursor/enable-snyk-pip-gate exists, finds any
       %pip/%!pip install cells in the exported .py and runs the same age +
       vulnerability checks as Gate 2. Blocks if any cell would install a
       too-new or vulnerable package, with a suggested safe version.
    4. **Snyk Code scan** — ``snyk code test`` on the exported ``.py``.

  All four steps must pass before notebook execution is allowed.

GATE 2 — pip install gate (enforced when .cursor/enable-snyk-pip-gate exists):
  Before any pip install (via a shell tool), the hook autonomously runs:

    1. **PyPI release-age check** — queries pypi.org/pypi/<pkg>/json and blocks
       packages whose latest (or pinned) version was published within the last
       24 hours (SNYK_PIP_GATE_MAX_AGE_HOURS). Also finds the newest version
       older than the threshold so the agent can retry with a safe pin.

    2. **Snyk open-source test** — runs ``snyk test`` on a temporary requirements
       file. Blocks on exit 1 (known vulnerabilities).

  On a too-new block the deny message includes a ``pip install pkg==X.Y.Z``
  retry command so the agent can immediately switch to the safe version.
  On a Snyk block the deny message includes Snyk's output (which often names
  the fixed version).

Env overrides:
  SNYK_PIP_GATE_MAX_AGE_HOURS   — recency threshold (default 24)
  COPILOT_PRETOOL_NBCONVERT_TIMEOUT — nbconvert timeout seconds (default 120)
  COPILOT_PRETOOL_SNYK_TIMEOUT  — snyk timeout seconds (default 300)

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

# Tool names that write/edit notebook cell content via dedicated notebook tools
_TOOLNAME_NOTEBOOK_EDIT = re.compile(
    r"(notebook.?edit|edit.?cell|cell.?edit|insert.?cell|replace.?cell|"
    r"write.?cell|notebook.?write|create.?cell|update.?cell|set.?cell)",
    re.I,
)

# Generic file-write tool names that can also overwrite a .ipynb
_TOOLNAME_FILE_WRITE = re.compile(r"^(edit|write|str_replace_editor|replace_in_file|overwrite)$", re.I)

# Arg keys that carry cell source in NotebookEdit-style tool calls
_CELL_SOURCE_KEYS = ("new_source", "source", "cell_source", "content", "text", "code", "src")

# Arg keys that carry the new file body in Edit/Write tool calls
_FILE_CONTENT_KEYS = ("new_string", "content", "new_content", "text", "file_content")

_TOOLNAME_NOTEBOOK_EXEC = re.compile(
    r"(jupyter|ipython|nbconvert|papermill|nbclient|execute_?cell|run_?cell|notebook_?run|run_?notebook)",
    re.I,
)

_NB_PATH_KEYS = ("path", "notebook", "input", "input_path", "notebook_path", "file", "filePath", "file_path")

# Strips version specifiers and extras to extract the bare package name
_PKG_NAME_STRIP_RE = re.compile(r"[=<>!~\[\]@;].*$")

# Patterns nbconvert produces for %pip and !pip magic cells
_NB_PIP_LINE_MAGIC_RE = re.compile(
    r"""run_line_magic\s*\(\s*['"]pip['"]\s*,\s*['"](install[^'"]*)['"]\s*\)""",
    re.I,
)
_NB_SYSTEM_PIP_RE = re.compile(
    r"""\.system\s*\(\s*['"]((?:!pip3?|pip3?)\s+install[^'"]*)['"]\s*\)""",
    re.I,
)


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
# Gate 1 — notebook execution (export + pip cell scan + Snyk Code)
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


def _extract_pip_installs_from_py(py: Path) -> list[str]:
    """
    Find pip install commands embedded in an nbconvert-exported .py.
    nbconvert converts ``%pip install foo`` → ``run_line_magic('pip', 'install foo')``
    and ``!pip install foo``  → ``.system('pip install foo')``.
    Returns a list of normalised ``pip install ...`` command strings.
    """
    try:
        content = py.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    commands: list[str] = []

    for m in _NB_PIP_LINE_MAGIC_RE.finditer(content):
        arg = m.group(1).strip()  # e.g. 'install numpy pandas'
        commands.append(f"pip {arg}")

    for m in _NB_SYSTEM_PIP_RE.finditer(content):
        cmd = m.group(1).lstrip("!")
        commands.append(cmd.strip())

    return commands


def _export_and_snyk_scan_before_notebook_execution(cwd: str, tool_name: str, tool_args: dict) -> bool:
    """
    Run nbconvert, optionally check pip cells, then snyk code test before
    allowing notebook execution. Returns True to proceed; False if denied.
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

    # Run pip gate checks on any %pip / !pip install cells inside the notebook.
    # This closes the gap where an agent runs the full notebook and a cell
    # installs a package that bypasses the shell-tool pip gate.
    if _pip_gate_enabled(cwd):
        pip_cmds = _extract_pip_installs_from_py(py)
        for cmd in pip_cmds:
            pkgs = _parse_pip_packages(cmd)
            if not pkgs:
                continue
            max_age = float(os.environ.get("SNYK_PIP_GATE_MAX_AGE_HOURS", "24"))
            too_new_lines: list[str] = []
            for spec in pkgs:
                age, safe_ver = _pypi_check(spec, max_age)
                if age is not None and age < max_age:
                    entry = f"{_strip_pkg_name(spec)} (released {age:.1f}h ago)"
                    if safe_ver:
                        entry += f" → use =={safe_ver}"
                    too_new_lines.append(entry)
            if too_new_lines:
                _deny(
                    "Notebook execution blocked: notebook cell(s) contain pip install "
                    "commands with packages released within the last "
                    f"{max_age:.0f} hours:\n"
                    + "\n".join(f"  • {l}" for l in too_new_lines)
                    + "\nPin a safe version or remove the cell before executing."
                )
                return False
            passed, reason = _snyk_test_packages(pkgs, cwd)
            if not passed:
                _deny(
                    "Notebook execution blocked: notebook cell(s) contain pip install "
                    f"commands with known vulnerabilities.\n{reason}"
                )
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
# Gate 2 — pip install (autonomous: PyPI age + safe-version suggestion + Snyk)
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
            if t in ("-e", "--editable"):
                return None  # can't gate editable installs
            if t in ("-r", "--requirement"):
                return None  # signal: has requirements file; caller must handle
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


def _reqs_file_path_from_command(command: str, cwd: str) -> Path | None:
    """
    If the command contains ``-r <file>`` or ``--requirement <file>``,
    return the resolved Path if the file exists; otherwise None.
    """
    m = re.search(r"(?:-r|--requirement)\s+([^\s]+)", command, re.I)
    if not m:
        return None
    raw = m.group(1).strip().strip("'\"")
    p = Path(raw) if Path(raw).is_absolute() else Path(cwd) / raw
    resolved = p.resolve()
    return resolved if resolved.is_file() else None


def _parse_reqs_file(path: Path) -> list[str]:
    """
    Parse a requirements.txt into package specs, skipping flags, VCS URLs,
    chained -r includes, and blank/comment lines.
    """
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    packages: list[str] = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            continue  # -r, --index-url, etc.
        if "://" in line or line.startswith("git+"):
            continue  # VCS / URL deps — cannot version-check via PyPI
        line = re.split(r"\s+#", line)[0].strip()  # strip inline comments
        if line:
            packages.append(line)
    return packages


def _extract_pip_from_cell_source(tool_args: dict) -> list[str]:
    """
    Return pip install command lines found in cell-source-like tool args.
    Scans each _CELL_SOURCE_KEYS field directly so leading-whitespace anchors fire.
    """
    commands: list[str] = []
    for key in _CELL_SOURCE_KEYS:
        val = tool_args.get(key)
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
    code cell's source. Used for Edit/Write tool calls on .ipynb files and
    for Cursor's beforeFileEdit payload which delivers the full notebook JSON.
    Falls back to a permissive text scan if JSON parsing fails.
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
        # Not valid notebook JSON — do a permissive text scan
        # (e.g. Edit tool sending a partial new_string fragment)
        _pip_bare = re.compile(
            r"""(?:^|[^a-zA-Z0-9_])(%pip|!pip3?|pip3?)\s+install\b(.+)""", re.I | re.M
        )
        for m in _pip_bare.finditer(text):
            commands.append(f"{m.group(1)} install {m.group(2).split(chr(10))[0].strip()}")
    return commands


def _strip_pkg_name(spec: str) -> str:
    """Extract bare package name from a spec like 'numpy>=1.0' or 'pandas[excel]'."""
    return _PKG_NAME_STRIP_RE.sub("", spec).strip()


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

    def _earliest_upload(files: list[dict]) -> datetime | None:
        times = [_parse_dt(f.get("upload_time_iso_8601") or f.get("upload_time") or "") for f in files]
        valid = [t for t in times if t is not None]
        return min(valid) if valid else None

    all_releases: dict = data.get("releases") or {}
    target_ver = pinned or (data.get("info") or {}).get("version")
    if not target_ver:
        return None, None

    target_files = all_releases.get(target_ver, [])
    target_dt = _earliest_upload(target_files)
    if target_dt is None:
        return None, None

    target_age = (now - target_dt).total_seconds() / 3600.0

    if target_age >= max_age_hours:
        # Already old enough — no safe-version search needed
        return target_age, None

    # Find the newest non-yanked version that is old enough
    safe_candidates: list[tuple[str, datetime]] = []
    for ver, files in all_releases.items():
        if not files:
            continue
        # Skip yanked releases
        if any(f.get("yanked") for f in files):
            continue
        dt = _earliest_upload(files)
        if dt is None:
            continue
        age = (now - dt).total_seconds() / 3600.0
        if age >= max_age_hours:
            safe_candidates.append((ver, dt))

    if not safe_candidates:
        return target_age, None

    # Sort by upload time descending → pick the most recent "safe" release
    safe_candidates.sort(key=lambda x: x[1], reverse=True)
    return target_age, safe_candidates[0][0]


def _osv_check_packages(packages: list[str]) -> tuple[bool, str]:
    """
    Query OSV.dev for known vulnerabilities by package name+version.
    Returns (passed, failure_reason).  Fails open if the API is unreachable.
    OSV doesn't require pip resolution or a local venv — works pre-install.
    """
    OSV_URL = "https://api.osv.dev/v1/querybatch"
    queries = []
    specs = []
    for spec in packages:
        name = _strip_pkg_name(spec)
        ver_match = re.search(r"==([^\s,;]+)", spec)
        version = ver_match.group(1) if ver_match else None
        # OSV without a pinned version returns all historical CVEs for the package —
        # not actionable.  Only check when the agent has specified an exact version.
        if not version:
            continue
        queries.append({"package": {"name": name, "ecosystem": "PyPI"}, "version": version})
        specs.append(spec)

    if not queries:
        return True, ""

    try:
        body = json.dumps({"queries": queries}).encode()
        req = urllib.request.Request(
            OSV_URL,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "snyk-pip-gate/1.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
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


def _snyk_test_packages(packages: list[str], cwd: str) -> tuple[bool, str]:
    """
    Run ``snyk test`` as a supplementary check.
    Returns (passed, failure_reason). Fails open if snyk is unavailable or
    if pip can't resolve the package graph (422 / exit 2).
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
        return True, ""
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    if r.returncode == 0:
        return True, ""

    # exit 2 = Snyk couldn't resolve the dep graph (native extensions, auth issues, etc.)
    # Fall back to OSV result rather than hard-blocking on infra errors.
    if r.returncode != 1:
        return True, ""

    tail = ((r.stderr or "") + (r.stdout or ""))[-1500:]
    return False, f"Snyk test found issues:\n{tail}"


def _run_pip_gate_checks(packages: list[str], cwd: str, context: str = "pip install") -> None:
    """
    Core age + Snyk checks for a resolved list of package specs.
    Calls _deny() and returns if any check fails; returns silently to allow.
    context is used in deny messages to describe where the packages came from.
    """
    max_age_hours = float(os.environ.get("SNYK_PIP_GATE_MAX_AGE_HOURS", "24"))

    # 1. PyPI release-age check
    too_new: list[tuple[str, float, str | None]] = []
    for spec in packages:
        age, safe_ver = _pypi_check(spec, max_age_hours)
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

        msg = (
            f"{context} blocked: the following package(s) were released within the last "
            f"{max_age_hours:.0f} hours and may be malicious:\n" + "\n".join(lines)
        )
        if retry_specs:
            msg += f"\nRetry with: pip install {' '.join(retry_specs)}"
        else:
            msg += f"\nWait until the package(s) are at least {max_age_hours:.0f} hours old."
        _deny(msg)
        return

    # 2. OSV advisory check (works pre-install, no local env needed).
    # Only fires for pinned versions; unversioned specs skip (OSV returns all-time CVEs).
    passed, reason = _osv_check_packages(packages)
    if not passed:
        _deny(f"{context} blocked by OSV: {reason}")
        return

    # Snyk transitive-dep scanning is intentionally skipped here: it requires a
    # resolved pip graph and flags transitive/license issues that are too noisy for
    # a pre-install gate.  Snyk remains active in Gate 1 (notebook code scan).


def _check_pip_install(cwd: str, tool_name: str, tool_args: dict) -> None:
    """
    Gate 2 entry point for shell-tool pip install commands.
    Handles both inline package specs and -r requirements.txt.
    """
    if not _pip_gate_enabled(cwd):
        return

    command = _shell_command(tool_name, tool_args) or str(tool_args.get("command") or "")
    if not command or not _PIP_RE.search(command):
        return

    packages = _parse_pip_packages(command)
    if packages is None:
        # _parse_pip_packages returns None for -r, -e, VCS URLs.
        # For -r requirements.txt, read the file and gate its contents.
        reqs_path = _reqs_file_path_from_command(command, cwd)
        if reqs_path is None:
            # Editable install or unresolvable requirements file — skip gate
            return
        packages = _parse_reqs_file(reqs_path)
        if not packages:
            return
        _run_pip_gate_checks(packages, cwd, context=f"pip install -r {reqs_path.name}")
        return

    _run_pip_gate_checks(packages, cwd)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _check_notebook_cell_edit(cwd: str, tool_name: str, tool_args: dict) -> None:
    """
    Gate 3 — fires when an agent writes a notebook cell containing pip install.
    Covers two paths:
      • NotebookEdit-family tools: cell source is a structured arg (new_source etc.)
      • Edit/Write tools on .ipynb: new content is raw notebook JSON or a fragment
    Blocks the write if any package fails the age or Snyk check.
    """
    if not _pip_gate_enabled(cwd):
        return

    pip_cmds: list[str] = []

    if _TOOLNAME_NOTEBOOK_EDIT.search(tool_name):
        # Dedicated notebook cell editor — cell source is in a structured arg
        pip_cmds = _extract_pip_from_cell_source(tool_args)

    elif _TOOLNAME_FILE_WRITE.search(tool_name):
        # Generic Edit / Write tool — check if target is a .ipynb
        target = ""
        for k in ("path", "file_path", "filename", "filepath"):
            target = str(tool_args.get(k) or "")
            if target:
                break
        if not target.lower().endswith(".ipynb"):
            return
        # Extract the body being written and scan it as notebook JSON
        body = ""
        for k in _FILE_CONTENT_KEYS:
            body = str(tool_args.get(k) or "")
            if body:
                break
        if body:
            pip_cmds = _pip_installs_from_notebook_json(body)

    if not pip_cmds:
        return

    for cmd in pip_cmds:
        normalised = re.sub(r"^[%!]", "", cmd).strip()
        pkgs = _parse_pip_packages(normalised)
        if not pkgs:
            continue
        _run_pip_gate_checks(pkgs, cwd, context="Notebook cell pip install")


def main() -> None:
    raw = os.read(0, 1 << 20).decode("utf-8", errors="replace")
    try:
        data = json.loads(raw) if raw.strip() else {}
    except Exception:
        return

    cwd, tool_name, tool_args = _normalize_pre_tool_payload(data)

    # Gate 3: block pip installs being written into notebook cells at edit time
    _check_notebook_cell_edit(cwd, tool_name, tool_args)

    if _looks_like_agent_notebook_cell_execution(tool_name, tool_args):
        if not _export_and_snyk_scan_before_notebook_execution(cwd, tool_name, tool_args):
            return

    if tool_name.lower() not in _SHELL_TOOLS:
        return

    # Gate 2: block pip install shell commands (including -r requirements.txt)
    _check_pip_install(cwd, tool_name, tool_args)


if __name__ == "__main__":
    main()
