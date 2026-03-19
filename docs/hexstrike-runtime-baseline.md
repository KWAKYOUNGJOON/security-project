# HexStrike Runtime Baseline

This note captures the repository-side runtime baseline for HexStrike-related tooling in pre-target mode.

## Date

- Baseline captured on `2026-03-20`
- Working directory: `d:\security-project`

## Current observation

The current shell-level checks recorded in [runtime-baseline.json](/d:/security-project/intake/web/hexstrike-ai/run-001/raw/runtime-baseline.json) show:

- `python --version` returned `3.14.3`
- `Get-Command hexstrike*` did not resolve a command in the current PowerShell session
- `python -m pip show hexstrike-ai` reported package not found
- `python -m pip show hexstrike-mcp` reported package not found
- `importlib.metadata` probes for `hexstrike-ai`, `hexstrike_mcp`, `hexstrike-mcp`, `hexstrike-server`, and `hexstrike_server` reported package not found in the current Python environment

This is a runtime baseline only. It does not imply HexStrike cannot run elsewhere on the host. It only records what was visible from this repository session on `2026-03-20`.

## Capture method

When a local HexStrike runtime becomes visible in this workspace, capture the baseline into `intake/web/hexstrike-ai/<run-id>/raw/` using file-based probes only:

1. Command discovery

```powershell
Get-Command hexstrike*
```

2. Package discovery

```powershell
python -m pip show hexstrike-ai
python -m pip show hexstrike-mcp
```

3. Python distribution metadata

```powershell
@'
import importlib.metadata as m
for name in ["hexstrike-ai", "hexstrike_mcp", "hexstrike-mcp", "hexstrike-server", "hexstrike_server"]:
    try:
        dist = m.distribution(name)
        print(name, dist.metadata.get("Name", name), dist.version)
    except Exception as exc:
        print(name, type(exc).__name__)
'@ | python -
```

4. Optional version probes only if a local executable is already known

```powershell
hexstrike_server --version
hexstrike_mcp --version
```

Do not add any probe that starts a scan, opens a target connection, crawls, authenticates, or launches a subprocess scanner against a Web asset.

## Storage rule

- Runtime baseline files stay under `intake/.../raw/`
- Format observations from raw HexStrike-style payloads stay under `intake/.../derived/format-observation.json`
- Case-level normalized/reviewed/report artifacts remain under `cases/.../derived`
