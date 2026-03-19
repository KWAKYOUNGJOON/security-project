# schemas(스키마)

This folder is reserved for reusable data shape definitions shared across automation and reporting workflows.

## Intended use

Store schema guidance for objects such as:
- targets
- findings
- evidence items
- normalized scan records
- report payloads

## Phase-1 expectation

The current Web-only baseline now defines the first shared automation contracts here:
- `normalized-finding.schema.json`
- `report-payload.schema.json`

These schemas are validated by the local `apps/report-automation` CLI before derived artifacts are written.

## Naming guidance

Prefer descriptive schema names such as:
- `finding.schema.json`
- `report-payload.schema.json`
- `target.schema.json`

Keep names in English only.
