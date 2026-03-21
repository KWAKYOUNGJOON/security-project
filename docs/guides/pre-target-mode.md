# Pre-Target Mode

Pre-target mode exists so the repository can prepare HexStrike intake handling before a local Web practice target is available.

## Allowed

- Create intake folder structure under `intake/`
- Capture runtime baseline facts from the local shell and Python environment
- Store immutable raw payload files
- Generate file-based `format-observation.json`
- Generate file-based intake provenance
- Rehearse the parser with synthetic raw fixtures kept outside the live intake namespace

## Forbidden

- Network scans
- Crawling
- Authentication attempts
- Port connections
- External target validation
- Treating HexStrike output as a confirmed finding source

## Boundary

- `intake/...`: raw originals, runtime baseline captures, notes, manifest, format observation, intake provenance
- `cases/...`: normalized findings, reviewed findings, review log, report payload, rendered previews

Do not place normalized or reviewed case artifacts in `intake/`.
Do not place live intake originals in `cases/`.

## Command

This guide documents a pre-target, file-only legacy workflow.
It is not the canonical READY execution path.
For READY execution and READY evidence, use `docs/READY_EXECUTION_CONTRACT.md` and run from `app/vuln-pipeline`.
The canonical real-input schema is limited to `data/inputs/real/burp/burp-findings.json`, `data/inputs/real/nuclei/nuclei-findings.json`, `data/inputs/real/httpx/httpx-hosts.json`, and `data/inputs/real/manual/manual-findings.json`.

Run from `apps/report-automation`:

```powershell
python -m src.cli.main validate-live-hexstrike --run intake\web\hexstrike-ai\run-001
python -m src.cli.main validate-live-hexstrike --run intake\synthetic\hexstrike-ai\rehearsal-001
```

This command is file-based only. It reads listed raw payloads, emits `derived/format-observation.json`, and records `derived/provenance.json`. It does not start HexStrike, spawn a scanner subprocess, or touch a network target.
