# vuln-pipeline

`app/vuln-pipeline` is the canonical READY(1) execution root.

## Canonical Execution

- Working directory: `app/vuln-pipeline`
- Official entrypoint: `python -m vuln_pipeline.cli.main`
- Forbidden path: `apps/report-automation/src/cli/main.py`
- Forbidden reason: this path is legacy for a different scaffold and is not the READY(1) execution contract

## Environment

- Minimum Python version: `3.11.x`
- Official install command: `python -m pip install -e .`
- Official smoke command: `python -m vuln_pipeline.cli.main smoke --output-dir ../../outputs/ready1/smoke`

## Inputs

- Input root: `data/inputs/real`
- Allowed subpaths: `burp/`, `nuclei/`, `httpx/`, `manual/`
- READY(1) minimal real-input set:
  - `burp/burp-findings.json`
  - `nuclei/nuclei-findings.json`
  - `httpx/httpx-hosts.json`
  - `manual/manual-findings.json`

## Outputs

Each smoke run writes:

- `input_preflight.json`
- `release_readiness.json`
- `submission_gate.json`

## Optional Comparison

Repeated-run comparison can be checked with:

```powershell
python -m vuln_pipeline.cli.main compare-runs --run-dir ../../outputs/ready1/run-1 --run-dir ../../outputs/ready1/run-2 --run-dir ../../outputs/ready1/run-3
```
