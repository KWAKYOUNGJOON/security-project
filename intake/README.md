# intake

Immutable intake area for pre-target observation and raw source retention.

## Purpose

- Keep original intake files separate from `cases/`.
- Allow file-based format observation before a local Web target is ready.
- Preserve the boundary between source observation and report-generation artifacts.

## Boundary

Use `intake/` for:
- `manifest.json`
- `notes.md`
- raw baseline captures
- raw HexStrike-style payloads
- `derived/format-observation.json`
- `derived/provenance.json`

Do not use `intake/` for:
- normalized findings
- reviewed findings
- report payloads
- report previews

Those remain under `cases/web/<case-id>/derived` and `cases/web/<case-id>/output`.

## Layout

Live pre-target runs:

```text
intake/web/hexstrike-ai/run-001/
  manifest.json
  notes.md
  raw/
  derived/
```

Synthetic parser rehearsal runs:

```text
intake/synthetic/hexstrike-ai/rehearsal-001/
  manifest.json
  notes.md
  raw/
  derived/
```
