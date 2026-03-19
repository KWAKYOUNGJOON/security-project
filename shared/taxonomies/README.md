# taxonomies

This folder defines explicit Web taxonomy contracts used by `apps/report-automation`.

## Policy

- Never rely on a bare code string alone.
- Always persist `taxonomy.name`, `taxonomy.version`, and `canonical_key` together.
- `canonical_key` is the stable internal identifier used to avoid collisions between legacy and external taxonomies.
- Display text in the report may still use the human-facing `code` and `title_ko`.

## Current files

- `web-legacy-template.json`
- `web-kisa-2026.json`

## Example collision

- `SF` in the legacy template taxonomy maps to `session_fixation`
- `SF` in the KISA 2026 Web taxonomy maps to `ssrf`

Because of this, `code` by itself is never enough to drive internal classification or automation behavior.
