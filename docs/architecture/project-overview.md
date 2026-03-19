# Project Overview

## Purpose

This repository is a security assessment workspace for collecting evidence, organizing engagement data, and preparing report deliverables. The current implementation scope is Web only. The target architecture is broader and will later support Web + API + Server assessment workflows without replacing the current Web baseline.

## Phase 1 baseline

Phase 1 focuses on a stable, understandable repository with minimal automation and low operational friction.

Primary characteristics:
- Web assessment workflow is the only active implementation path.
- Python is the default automation language.
- `HexStrike-AI` is the initial phase-1 integration target.
- Existing report rendering assets stay under `apps/report-template`.
- New report preparation logic starts under `apps/report-automation`.

## Component model

### `apps/report-template`

Rendering-oriented asset set for Web assessment reports. It already contains working source files, tests, and generated output examples. In phase 1, this app remains the primary report rendering component.

### `apps/report-automation`

Automation-oriented Python scaffold that prepares structured assessment data. The initial flow is intentionally simple:

1. Collect source data
2. Parse raw payloads
3. Normalize findings
4. Enrich severity and reporting metadata
5. Build a report-ready payload

This app is adapter-ready rather than integration-heavy. The first integration is a local-safe `HexStrike-AI` stub so development can proceed without external services.

### `shared`

Repository-level shared resources for schema definitions, mappings, prompts, and utilities. These directories should contain reusable assets, not engagement-specific output.

### `engagements`

Per-engagement working areas for scope definition, targets, recon, scans, evidence, findings, notes, and report drafts. This is where assessment data should live during execution.

## Architectural boundaries

- `archive/original-sources` is preserved reference material and must not be modified.
- Current Web implementation should remain stable and readable.
- API and Server support should be added incrementally with new folders, schemas, and adapters rather than by mixing unfinished logic into the Web workflow.
- Dependencies must stay minimal during phase 1.

## Expected growth path

Short term:
- Use the phase-1 pipeline to convert collected Web findings into a report payload.
- Keep evidence and engagement state organized in `engagements/`.
- Keep the report template isolated from future integration logic.

Later:
- Add API-specific collectors, parsers, and mappings.
- Add Server-specific evidence patterns and normalization rules.
- Introduce more complete shared schemas once the Web baseline is stable.
- Expand report payload generation so multiple delivery formats can share the same normalized data.
