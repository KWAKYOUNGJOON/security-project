# src(소스코드)

Source code for the phase-1 report automation pipeline.

## Pipeline stages

- `collectors/`: fetch or assemble source snapshots
- `parsers/`: translate raw source payloads into structured records
- `normalizers/`: reshape records into a stable internal finding model
- `enrichers/`: add reporting metadata such as severity mapping
- `generators/`: build report-ready payloads
- `integrations/`: adapter modules for external systems
- `cli/`: local command-line entry points

## Current status

The current implementation is intentionally minimal and Web-only. It exists to prove the local pipeline shape without introducing external dependencies or pretending that production integrations already exist.
