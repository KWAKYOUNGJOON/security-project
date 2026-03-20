# Target-Ready Checklist

Checklist for the point where pre-target mode ends and the first live-local-lab smoke run becomes eligible.

## Required before live-local-lab smoke run

- The target is a local Web target and is explicitly approved for testing.
- The target is OWASP Juice Shop only for this phase.
- The canonical target URL is documented as `http://192.168.10.130:3000`.
- The observed entry route `http://192.168.10.130:3000/#/` is recorded as notes only, not as the canonical target.
- The scope is limited to one target and no external assets.
- Previous Ubuntu resource pressure is acknowledged and stop conditions are written down.
- The first live run ID is decided as `run-juice-001`.
- The intake folder exists before scanning starts.
- The team agrees that live intake artifacts stay under `intake/` until the shape is understood.
- The team agrees that no automatic promotion into `cases/` is allowed.
- A visible HexStrike scanner entrypoint exists in the current execution environment.
- The scanner exposes real `help/version` output for low-impact controls.
- The scanner `help` output confirms enough controls to keep the run slow and narrow:
  - export or output path
  - target scope restriction
  - concurrency or single-worker control
  - pacing such as delay or jitter
  - crawl depth or request/page budget
  - runtime cap, timeout, or equivalent
  - retry behavior

## First steps after readiness

1. Capture the runtime baseline and save it under `intake/web/hexstrike-ai/run-juice-001/raw/`.
2. Run exactly one low-impact smoke scan against `http://192.168.10.130:3000` only if the required controls were confirmed from real scanner help output.
3. Save the first raw export only under `intake/web/hexstrike-ai/run-juice-001/raw/hexstrike-result.json`.
4. Run `validate-live-hexstrike` against that intake run to generate `derived/format-observation.json`.
5. Compare the live observation with the synthetic rehearsal output and document the shape delta.
6. Decide whether the live raw format is stable enough to promote into a case input mapping step.
7. Only then wire selected data into `cases/web/<case-id>/input/...`.
