# security-project

`security-project` is a security assessment workspace for vulnerability assessment, evidence management, and report automation.

## Scope

Current implementation scope:
- Web

Target scope:
- Web
- API
- Server

Phase 1 is intentionally Web-first. The repository is being normalized so current work stays stable while the folder model, shared assets, and automation paths can expand to API and Server later.

## Project priorities

- Keep the current assessment workflow lightweight and Python-first.
- Preserve useful existing assets, especially the working report template under `apps/report-template`.
- Build a minimal automation baseline under `apps/report-automation`.
- Keep `archive/original-sources` untouched as the preserved reference source.
- Use English-only folder and file names. Documentation may use `english-name(한글이름)` notation.

## Repository map

- `docs/`: architecture notes, workflow guides, checklists, and references
- `apps/`: executable project components
- `shared/`: reusable schemas, mappings, prompts, and utilities
- `engagements/`: engagement workspaces for scoped targets, evidence, findings, and reports
- `assets/`: reusable logos, icons, and sample data
- `scripts/`: setup, development, and release helpers
- `outputs/`: exported reports, evidence bundles, and presentation materials
- `archive/`: preserved originals and retired material

## Phase 1 app roles

### `apps/report-template`

Existing HTML/PDF report template for Web assessment deliverables. This is the current rendering-focused implementation and should remain stable.

### `apps/report-automation`

Minimal Python-ready scaffold for the phase-1 automation flow:

`collect -> parse -> normalize -> enrich -> build report payload`

The initial integration target is `HexStrike-AI`, implemented as a local-safe stub/adapter layer so the CLI runs without external services.

## Recommended local workflow

1. Define engagement scope and targets under `engagements/sample-folder` or a copied engagement folder.
2. Store raw scan outputs, screenshots, proxy traffic, and notes in the engagement workspace.
3. Run the phase-1 automation scaffold under `apps/report-automation` to prepare normalized payload data.
4. Use `apps/report-template` to render the Web assessment report.
5. Export final deliverables to `outputs/`.

Detailed guidance:
- [project-overview](docs/architecture/project-overview.md)
- [folder-policy](docs/architecture/folder-policy.md)
- [local-workflow](docs/guides/local-workflow.md)

## Conventions

- Do not modify `archive/original-sources`.
- Prefer reorganizing or documenting existing files instead of rewriting working assets.
- Keep dependencies minimal. Do not assume package installation during phase 1.
- Use Windows-safe paths and commands in documentation and examples.

## Current status

- Repository layout already aligns with the intended top-level structure.
- Core documentation has been normalized around the Web-only phase-1 baseline.
- `apps/report-automation` now carries a minimal executable scaffold for future growth.
- Future expansion should add API and Server-specific collectors, parsers, schemas, and templates without breaking the current Web path.
