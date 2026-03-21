Canonical smoke and contract-evaluation outputs belong under `data/runs/<run_id>`.

Rules:
- `run_id` must match `^run-\\d{8}T\\d{6}Z$`
- each run directory must contain `input_preflight.json`, `release_readiness.json`, and `submission_gate.json`
- dry-run or placeholder-based outputs may exist here, but they must remain `NOT_READY` or `BLOCKED`
- `apps/report-automation` outputs and `outputs/ready1/**` are not canonical READY evidence
