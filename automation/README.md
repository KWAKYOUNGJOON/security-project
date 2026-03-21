# automation

`automation/` is a small local Codex helper, not the repository's canonical report automation pipeline.

## Purpose

- Run ad hoc `codex exec ...` prompts against this repository.
- Save captured `stdout`, `stderr`, and status artifacts under `automation/runs/`.
- Iterate on a task from `automation/task.txt` with a simple follow-up prompt.

## Boundary

The productized phase-1 report pipeline lives under [`apps/report-automation`](/home/kyj/code/security-project/apps/report-automation/README.md). That app owns structured report-preparation logic for the Web workflow.

By contrast, [`orchestrator.py`](/home/kyj/code/security-project/automation/orchestrator.py) is only a repository-local wrapper around Codex CLI for exploratory or maintenance tasks. It should not be treated as part of the assessment/report pipeline architecture.
