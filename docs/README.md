# docs(문서)

Project-level documentation for the phase-1 Web baseline and the planned path to Web + API + Server.

## Contents

- `architecture/`: project structure, operating boundaries, and future growth model
- `guides/`: local working instructions and repeatable workflow notes
- `checklists/`: assessment checklist ownership and expected checklist categories
- `references/`: standards, mappings, examples, and external reference material

## Recommended starting points

- Canonical READY execution contract and command root:
  - `docs/READY_EXECUTION_CONTRACT.md`
  - `app/vuln-pipeline`
- [READY_EXECUTION_CONTRACT.md](READY_EXECUTION_CONTRACT.md)
- [architecture/project-overview.md](architecture/project-overview.md)
- [architecture/folder-policy.md](architecture/folder-policy.md)
- [guides/local-workflow.md](guides/local-workflow.md)
- [guides/pre-target-mode.md](guides/pre-target-mode.md)
- [guides/hexstrike-live-smoke-run.md](guides/hexstrike-live-smoke-run.md)
- [guides/hexstrike-operator-handoff.md](guides/hexstrike-operator-handoff.md)
- [hexstrike-runtime-baseline.md](hexstrike-runtime-baseline.md)
- [hexstrike-live-shape-analysis.md](hexstrike-live-shape-analysis.md)
- [checklists/target-ready-checklist.md](checklists/target-ready-checklist.md)

## Scope note

Current implementation is Web only. Documentation should keep that explicit while reserving room for API and Server additions later.

READY note:
- `docs/READY_EXECUTION_CONTRACT.md` is the single source of truth for READY execution.
- The canonical real-input schema is fixed there as `burp/burp-findings.json`, `nuclei/nuclei-findings.json`, `httpx/httpx-hosts.json`, and `manual/manual-findings.json` under `data/inputs/real/`.
- `apps/report-automation/**` materials may remain for legacy or pre-target workflows, but they are not canonical READY execution or READY evidence.
