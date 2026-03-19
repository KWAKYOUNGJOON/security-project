# Local Workflow

This guide describes the simplest supported phase-1 workflow for a local Web assessment run.

## Scope reminder

- Current implementation scope: Web
- Planned future scope: Web + API + Server

Use the current flow to keep Web work stable. Treat API and Server as future extensions, not active implementation paths inside phase 1.

## Suggested workflow

1. Prepare an engagement workspace.

   Start from `engagements/sample-folder` when creating a new working folder. Keep scope notes, targets, evidence, and findings inside the engagement directory rather than scattering them across the repository.

2. Capture assessment inputs.

   Store raw scanner exports under `scans/raw/`, screenshots under `evidence/screenshots/`, traffic captures under `evidence/traffic/`, and proxy exports under `evidence/burp/`.

3. Normalize working data.

   Convert or summarize raw material into `scans/normalized/` and `findings/` so the reporting workflow can consume cleaner inputs.

4. Run the automation scaffold.

   From `apps/report-automation`, run:

   ```powershell
   python -m src.cli.main
   ```

   This phase-1 CLI uses a local-safe `HexStrike-AI` stub and produces a report-ready JSON payload without requiring external services.

5. Review the generated payload.

   If you want a file output:

   ```powershell
   python -m src.cli.main --output ..\..\outputs\exports\sample-report-payload.json
   ```

6. Render the report.

   Use `apps/report-template` to maintain and build the HTML/PDF report assets for the current Web engagement workflow.

7. Publish final outputs.

   Place report deliverables, evidence bundles, or presentation exports under `outputs/` as needed.

## Operating guidance

- Keep evidence and customer-specific data inside `engagements/`.
- Keep reusable mappings, schemas, and prompts inside `shared/`.
- Do not modify `archive/original-sources`.
- Do not add heavyweight dependencies for phase 1.
- Prefer explicit file-based inputs and outputs over hidden local state.

## Future extension points

When API and Server scope is added later, the workflow should extend by introducing new collectors, parsers, and templates instead of changing the existing Web pipeline shape.
