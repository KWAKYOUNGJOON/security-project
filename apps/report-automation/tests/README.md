# tests(테스트)

Automation tests for the phase-1 report pipeline.

## Current test

- `test_smoke.py`: verifies that the local CLI and the end-to-end pipeline run successfully without external services
- `test_hexstrike_pretarget_intake.py`: verifies file-based pre-target HexStrike observation and fail-fast validation

## Guidance

Keep tests lightweight, deterministic, and dependency-free during phase 1.
