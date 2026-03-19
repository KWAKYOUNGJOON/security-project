# sample-folder(예시-진단건)

`engagements/sample-folder` is the reference layout for a phase-1 engagement workspace.

## Purpose

Use this folder as the baseline structure for a Web assessment engagement. Copy the structure when starting a new engagement and replace sample content with real project material.

## Folder overview

- `scope/`: engagement boundaries, assumptions, exclusions
- `targets/`: target inventory and environment notes
- `recon/`: reconnaissance notes and discovery outputs
- `scans/raw/`: unmodified raw scanner exports
- `scans/normalized/`: cleaned or transformed scan data
- `evidence/`: screenshots, traffic captures, proxy exports, and logs
- `findings/`: validated finding records
- `report/draft/`: working report outputs
- `report/final/`: approved deliverables
- `notes/`: analyst notes and coordination material

## Scope note

Current implementation is Web only. Keep API and Server material out of the active flow until those paths are added intentionally.

## Operating guidance

- Preserve raw source evidence before normalization.
- Keep engagement-specific data inside the engagement folder.
- Use `outputs/` only for broader export packaging or consolidated deliverables.
- Do not store archived originals here.
