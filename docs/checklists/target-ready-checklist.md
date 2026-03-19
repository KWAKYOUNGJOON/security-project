# Target-Ready Checklist

Draft checklist for the point when pre-target mode can end and a local Web practice target is ready.

## Required before moving past pre-target mode

- A local Web target exists and is explicitly in scope.
- The target is owned or authorized for local testing.
- The target base URL is documented and stable enough for repeatable runs.
- Test accounts, session state, and reset procedure are documented if authentication is required.
- A safe evidence storage path is prepared.
- Intake run naming for the first live raw payload is decided.
- File-based raw export format is known well enough to capture without guessing fields.
- The team agrees that pre-target observation artifacts and case artifacts remain separate.

## First steps after target readiness

1. Capture the first live HexStrike raw payload into `intake/web/hexstrike-ai/<run-id>/raw/`.
2. Run `validate-live-hexstrike` against that intake run to generate `format-observation.json`.
3. Compare live observation output with the synthetic rehearsal output and document shape deltas.
4. Decide whether the live raw format is stable enough to promote into a case input mapping step.
5. Only then wire the selected raw payload into a `cases/web/<case-id>/input/...` workflow.
