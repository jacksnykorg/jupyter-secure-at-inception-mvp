# Notebook → nbconvert → Snyk (Cursor + Copilot hooks)

This repo is a **minimal template** for a secure “Jupyter notebook as source-of-truth” workflow:

- You edit **`*.ipynb`**
- A Cursor hook exports the notebook to a sibling **`.py`** using `nbconvert`
- You run **Snyk Code** on the exported `.py` (optionally via Snyk CLI automatically after export)
- You fix findings **in the notebook**, re-export, and rescan

It also includes an optional **pip install gate** that enforces **Snyk package health checks before installs**.

## What’s in this repo

- **Agent guidance**
  - `AGENTS.md`: repo-level instructions for agents working with notebooks + Snyk
- **Cursor rules**
  - `.cursor/rules/agent-notebook-workflow.mdc`: always-applied rule describing the required workflow
- **Cursor hooks**
  - `.cursor/hooks.json`: wires hook events to scripts
  - `.cursor/hooks/nbconvert_on_ipynb_edit.py`: exports `.ipynb` → `.py` (and can run Snyk Code via CLI)
  - `.cursor/hooks/pip_install_gate.py`: blocks pip installs until `snyk_package_health_check` is run
- **Copilot hooks (Preview)**
  - `.github/hooks/hooks.json`: wires Copilot hook triggers to scripts
  - `.github/hooks/pre_tool_use.py`: best-effort pip install gate for agent tool calls
  - `.github/hooks/post_tool_use.py`: export `.ipynb` → `.py` after agent file edits (optional Snyk CLI scan)
- **Feature flag**
  - `.cursor/enable-snyk-pip-gate`: **empty file**; its presence enables the strict pip gate

## How the workflow works

### 1) Dependency vetting (before any install)

Before running any of these:

- `pip install ...`
- `python -m pip install ...`
- Notebook `%pip install ...` or `!pip install ...`

…run **Snyk package health checks** first:

- Tool: `snyk_package_health_check`
- Ecosystem: `pypi`
- For each package you plan to install

If the pip gate is enabled, installs are blocked until you do this.

### 2) Edit the notebook (source of truth)

All first‑party logic belongs in **`*.ipynb`**.

### 3) Export (automatic via hook)

When a notebook is edited/saved, the `afterFileEdit` hook runs:

- `python3 .cursor/hooks/nbconvert_on_ipynb_edit.py`

That script runs:

```bash
python3 -m nbconvert --to python path/to/notebook.ipynb
```

…which writes a sibling `path/to/notebook.py`.

### 4) Scan + fix loop (Snyk Code)

Scan the exported `.py`:

- **Via MCP**: `snyk_code_scan` (scan a file or a directory)
- **Via CLI**: `snyk code test <exported.py>`

If Snyk finds issues:

- Fix them **in the notebook**
- Save the notebook (re-export)
- Rescan until clean

## What runs automatically (by environment)

- **Cursor**
  - **pip gate**: enforced via `.cursor/hooks/pip_install_gate.py` (when `.cursor/enable-snyk-pip-gate` exists)
  - **export**: runs on `*.ipynb` edits via `.cursor/hooks/nbconvert_on_ipynb_edit.py`
  - **SAST**: optional via Snyk CLI when `SNYK_CODE_TEST_ON_EXPORT=1` (or run MCP `snyk_code_scan` manually)
- **GitHub Copilot hooks (Preview)**
  - **pip gate (best-effort)**: enforced for **agent tool calls** via `.github/hooks/pre_tool_use.py`
  - **export (best-effort)**: runs after **agent file edits** via `.github/hooks/post_tool_use.py`
  - **SAST**: optional via Snyk CLI when `SNYK_CODE_TEST_ON_EXPORT=1`

Important: Copilot hooks fire on **agent lifecycle/tool events**, not “file saved in your editor,” so behavior can differ from Cursor.

## Setup

### Required

- **Python 3**
- **nbconvert**

Install nbconvert:

```bash
python3 -m pip install nbconvert
```

### Optional (recommended): Snyk CLI for automatic scans on export

If you want the export hook to automatically run `snyk code test` after exporting:

1. Install Snyk CLI (see Snyk docs)
2. Authenticate:

```bash
snyk auth
```

3. Enable export-time scanning in your environment:

```bash
export SNYK_CODE_TEST_ON_EXPORT=1
```

With that env var set, `nbconvert_on_ipynb_edit.py` will run `snyk code test` on the exported `.py` after each notebook edit.

### Editor/agent support (Cursor vs Copilot)

- **Cursor**
  - Uses `.cursor/hooks.json` + `.cursor/hooks/*.py`
  - Runs exports automatically when you save/edit `*.ipynb` in Cursor
- **GitHub Copilot hooks (Preview)**
  - Uses `.github/hooks/hooks.json` + `.github/hooks/*.py`
  - Hooks run for **Copilot agent tool calls** (for example, when the agent uses a shell tool or edits a file)
  - This repo’s Copilot hook scripts are a **best-effort** port of the Cursor behavior (same intent, different lifecycle)

To use Copilot hooks, you generally just **clone the repo** and ensure your Copilot environment has hooks enabled (Preview). For Copilot cloud agent, the `.github/hooks/*.json` config must be present on the repository’s **default branch**.

## Performance notes

- **Fast path (typical)**:
  - The pip gate only adds meaningful work when the agent is about to run a `pip install...` command.
- **Slow path (opt-in)**:
  - `nbconvert` runs on notebook edits and scales with notebook size.
  - `snyk code test` can take seconds to minutes depending on project size and the Snyk backend. Running it after every notebook change is intentionally strict but can feel slow.

Recommendation: keep `SNYK_CODE_TEST_ON_EXPORT` **off** during rapid iteration, then turn it **on** (or run Snyk on demand) before merging/sharing.

## Verification / preview disclaimer

- **Verified**: this template’s automation has been exercised in **Cursor** using `.cursor/hooks.json`.
- **Copilot hooks**: provided as a **best-effort** port targeting the current Copilot Hooks (Preview) model. Hook semantics and tool names can vary by Copilot surface/version, so treat this as **“trust but verify”** in your environment.

## Enabling/disabling the pip install gate

### Enable (strict)

Keep this file present (contents don’t matter; it can be empty):

- `.cursor/enable-snyk-pip-gate`

Behavior:

- Any pip install is **blocked** until you run `snyk_package_health_check`
- After the health check, a one‑time “voucher” allows the **next** pip install

### Disable (non-blocking)

Delete the flag file:

- `.cursor/enable-snyk-pip-gate`

Behavior:

- Installs won’t be blocked by the gate
- The hook may still attempt a best-effort CLI `snyk test` fallback for simple installs when Snyk CLI is available

## Troubleshooting

- **Export didn’t happen**
  - Ensure `.cursor/hooks.json` is present and hooks are enabled in Cursor
  - Ensure `nbconvert` is installed in the same Python used by Cursor (`python3`)
- **I see a warning about IPython during export**
  - You can install `ipython` if you rely on IPython-specific syntax; otherwise it’s usually harmless
- **Snyk CLI isn’t running on export**
  - Confirm `snyk` is on your `PATH`
  - Confirm you ran `snyk auth`
  - Confirm `SNYK_CODE_TEST_ON_EXPORT=1` is set in the environment Cursor is using

## Security model / intent

- `.ipynb` is the **source of truth**
- exported `.py` is **generated output** for scanning and tooling
- findings are remediated **in the notebook**, never by patching the generated `.py` only

