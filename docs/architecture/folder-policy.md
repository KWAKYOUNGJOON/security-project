# Folder Policy

This document defines what belongs in each major repository area and what should stay out.

## Root folders

### `docs`

Use for repository documentation only: architecture notes, workflow guides, checklists, and references.

Do not store:
- engagement-specific evidence
- generated reports
- working scan data

### `apps`

Use for executable project components.

Current app split:
- `report-template`: report rendering assets and related tests
- `report-automation`: Python automation scaffold for structured data preparation

Do not store:
- archived originals
- engagement-specific raw evidence

### `intake`

Use for immutable intake runs and pre-target observation only.

Expected contents:
- run manifests
- notes
- runtime baseline captures
- raw HexStrike-style payloads
- derived intake observations
- intake provenance ledgers

Do not put:
- normalized findings
- reviewed findings
- report payloads
- report previews

### `shared`

Use for reusable assets that can serve multiple apps or future scopes.

Expected contents:
- `schemas/`: canonical shapes for findings, evidence, and report payloads
- `mappings/`: severity, CWE, OWASP, and other cross-reference tables
- `prompts/`: reusable prompt text for structured analysis and reporting
- `utils/`: shared helper code only when reuse is clear

Do not put one-off engagement files here.

### `engagements`

Use for active or sample assessment workspaces. Each engagement folder should keep the full working set for that assessment:
- scope definition
- targets
- recon
- raw and normalized scans
- evidence
- findings
- report drafts and finals
- working notes

This is the correct home for customer- or target-specific material.

### `assets`

Use for reusable non-code assets shared across multiple engagements or apps, such as logos, icons, and sanitized sample data.

### `scripts`

Use for lightweight repository helpers grouped by purpose:
- `setup/`
- `dev/`
- `release/`

Scripts should remain small, readable, and dependency-light.

### `outputs`

Use for exported deliverables that are intended to be collected outside the app folders, such as final reports, evidence bundles, presentation files, and export packages.

### `archive`

Use for preserved historical material and original sources. Treat `archive/original-sources` as read-only in normal repository work.

## App-specific guidance

### `apps/report-template`

Use for the report rendering implementation:
- report source HTML/CSS/JS assets
- build scripts
- template-specific tests
- generated sample outputs

Avoid mixing automation pipeline logic into this app.

### `apps/report-automation`

Use for the data preparation pipeline and supporting assets.

Expected folders:
- `src/collectors/`: source acquisition entry points
- `src/parsers/`: raw source to structured record translation
- `src/normalizers/`: canonical field shaping
- `src/enrichers/`: metadata augmentation such as severity mapping
- `src/generators/`: report payload builders
- `src/integrations/`: adapter-ready client modules
- `src/cli/`: local command-line entry points
- `configs/`: runtime configuration files
- `templates/`: future payload or export templates
- `tests/`: automation tests
- `logs/`: local run logs

## Naming and language rules

- Real folder and file names must stay English only.
- Documentation may use `english-name(한글이름)` notation.
- Prefer descriptive names over abbreviations unless the abbreviation is already standard.

## Phase 1 decision rule

If a new file does not clearly belong somewhere, prefer keeping it close to the current Web workflow and document the uncertainty instead of forcing a premature abstraction.
