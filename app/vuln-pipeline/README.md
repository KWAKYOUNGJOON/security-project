# vuln-pipeline

`app/vuln-pipeline` is the canonical execution root defined by [docs/READY_EXECUTION_CONTRACT.md](../../docs/READY_EXECUTION_CONTRACT.md).

## Canonical Commands

- Working directory: `app/vuln-pipeline`
- Official entrypoint: `python -m vuln_pipeline.cli.main`
- Environment preparation:
  - `cd app/vuln-pipeline`
  - `python -m pip install -e .`
- Canonical smoke command:
  - `python -m vuln_pipeline.cli.main smoke --run-id <run_id>`
- Canonical test command:
  - `python -m pytest -q -m must_pass tests/test_fixture_smoke_e2e.py`

## Contract Notes

- Contract Python version: `3.11.x`
- Interpreter pin file: `app/vuln-pipeline/.python-version` -> `3.11`
- Packaging enforcement: `pyproject.toml` requires `>=3.11,<3.12`
- Contract `run_id` rule: `run-<YYYYMMDDTHHMMSSZ>`
- Contract `run_id` regex: `^run-\d{8}T\d{6}Z$`
- Canonical run output location: `data/runs/<run_id>`
- Forbidden READY evidence root: `apps/report-automation/**`
- As of `2026-03-21`, placeholder-only `real` inputs still mean the canonical result must stay `BLOCKED`.

## Inputs

- Canonical real input schema:
  - `data/inputs/real/burp/burp-findings.json`
  - `data/inputs/real/nuclei/nuclei-findings.json`
  - `data/inputs/real/httpx/httpx-hosts.json`
  - `data/inputs/real/manual/manual-findings.json`
- The parent roots must still exist:
  - `data/inputs/real/burp`
  - `data/inputs/real/nuclei`
  - `data/inputs/real/httpx`
  - `data/inputs/real/manual`
- README or placeholder files may remain for structure documentation, but they never satisfy the canonical manifest on their own and missing canonical files keep the gate `BLOCKED`.
- Synthetic and dry-run support must stay separate from `real` evidence. Test fixtures live under `tests/fixtures/synthetic`.

## Python 3.11 Activation

- Contract commands only count when `python` resolves to `3.11.x`.
- Typical Windows flow:
  - `cd app/vuln-pipeline`
  - `py -3.11 -m venv .venv`
  - `.venv\\Scripts\\Activate.ps1`
  - `python -m pip install -e .`
  - `python -m pytest -q -m must_pass tests/test_fixture_smoke_e2e.py`
- If `py -3.11` is unavailable, the canonical state remains `BLOCKED`.

## Outputs

Each smoke run writes these artifacts under `data/runs/<run_id>`:

- `input_preflight.json`
- `release_readiness.json`
- `submission_gate.json`

## Comparison

Repeated-run comparison can be checked with:

```powershell
python -m vuln_pipeline.cli.main compare-runs --run-dir ../../data/runs/<run-1> --run-dir ../../data/runs/<run-2> --run-dir ../../data/runs/<run-3>
```
