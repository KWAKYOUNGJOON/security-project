# report-template(보고서-템플릿)

`apps/report-template` contains the existing HTML/PDF reporting implementation for the current Web assessment workflow.

## Role in this repository

- Current implementation scope: Web
- Long-term repository target: Web + API + Server
- Current responsibility: render and validate the report deliverable for Web engagements

This folder already contains meaningful working assets and should be treated as the stable rendering side of the project, not as a place to introduce broad automation concerns.

## Existing implementation summary

The current template already supports:
- self-contained HTML output
- print-safe PDF generation through the build script
- report source editing under `report-src/`
- validation-focused template tests
- generated sample outputs under `dist/`

The phase-1 repository baseline preserves this work and documents how it fits with the new automation scaffold under `apps/report-automation`.

## Key contents

- `build_report.py`: build entry point for HTML/PDF generation
- `report-src/`: source HTML, CSS, JavaScript, templates, partials, and sample data
- `tests/`: template-specific safety and rendering checks
- `contracts/`: report payload contract notes and example payloads from the automation side
- `dist/`: generated sample outputs and validation artifacts
- `assets/`: template-local assets
- `scripts/`: template-local helper scripts

## Quick start

From `apps/report-template`:

```powershell
python build_report.py --dataset default
```

Expected primary outputs:
- `dist/report.html`
- `dist/report.pdf`

## Working guidance

- Edit report source assets under `report-src/`.
- Use `build_report.py` to regenerate outputs.
- Keep report-template focused on rendering concerns.
- Route future collection, normalization, and integration logic to `apps/report-automation`.

## Notes carried forward from the existing implementation

- `dist/report.html` and `dist/report.pdf` are the main sample deliverables.
- Additional validation artifacts in `dist/` support layout and quality checks.
- The existing test suite reflects security-aware handling in the template build path.
- Generated outputs may be refreshed locally as part of report work.

## Preservation rules

- Do not copy changes back into `archive/original-sources`.
- Do not move template automation responsibilities into this app unless they are directly about rendering.
- Prefer Windows-safe local commands and paths in repository documentation.
