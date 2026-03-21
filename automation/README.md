# automation

`automation/` is a small local Codex helper, not the repository's canonical report automation pipeline.

## Purpose

- Run ad hoc `codex exec ...` prompts against this repository.
- Save captured `stdout`, `stderr`, and status artifacts under `automation/runs/`.
- Iterate on a task from `automation/task.txt` with a simple follow-up prompt.
- Manage a manual ChatGPT <-> Codex handoff loop with repo-local state under `automation/loop/`.

## Boundary

The productized phase-1 report pipeline lives under [`apps/report-automation`](/home/kyj/code/security-project/apps/report-automation/README.md). That app owns structured report-preparation logic for the Web workflow.

By contrast, [`orchestrator.py`](/home/kyj/code/security-project/automation/orchestrator.py) is only a repository-local wrapper around Codex CLI for exploratory or maintenance tasks. It should not be treated as part of the assessment/report pipeline architecture.

## ChatGPT <-> Codex Loop

[`chatgpt_codex_loop.py`](/home/kyj/code/security-project/automation/chatgpt_codex_loop.py) is a small repo-local utility for a semi-automatic file-based handoff workflow:

- Generate the next ChatGPT request from the current goal and latest saved state.
- Save a ChatGPT reply, extract the required `## CODEX_PROMPT` section, and store it for Codex.
- Save the latest Codex reply and advance the iteration counter.

State lives under:

- `automation/loop/state.json`
- `automation/loop/chatgpt/`
- `automation/loop/codex/`
- `automation/loop/prompts/`

Set `CHATGPT_CODEX_LOOP_DIR=/tmp/my-loop` to redirect that loop root for isolated dry runs or tests. If the variable is unset, the default `automation/loop/` location is used unchanged.

One full cycle:

```bash
python3 automation/chatgpt_codex_loop.py init --goal "Find the next safe repo improvement"
python3 automation/chatgpt_codex_loop.py next-chatgpt
# paste the generated request into ChatGPT, then save the full reply:
python3 automation/chatgpt_codex_loop.py save-chatgpt-reply < chatgpt_reply.md
python3 automation/chatgpt_codex_loop.py show-codex-prompt
# paste that prompt into Codex, then save the full reply:
python3 automation/chatgpt_codex_loop.py save-codex-reply < codex_reply.md
python3 automation/chatgpt_codex_loop.py status
```

Example:

```bash
python3 automation/chatgpt_codex_loop.py init --goal "Review automation/ and suggest the next safe improvement"
python3 automation/chatgpt_codex_loop.py next-chatgpt > /tmp/chatgpt_request.md
```

Convenience options:

- Use `save-chatgpt-reply --file <path>` to save a full ChatGPT reply from a file instead of piping stdin.
- Use `save-codex-reply --file <path>` to save a full Codex reply from a file instead of piping stdin.
- Use `next-chatgpt --copy` to print the generated request and also copy it to the system clipboard.
- Use `show-codex-prompt --copy` to print the latest extracted prompt and also copy it to the clipboard.
- Use `status --verbose` to show latest artifact paths plus short readable previews.

Example cycle with the convenience options:

```bash
python3 automation/chatgpt_codex_loop.py init --goal "Find the next safe automation improvement"
python3 automation/chatgpt_codex_loop.py next-chatgpt --copy
python3 automation/chatgpt_codex_loop.py save-chatgpt-reply --file /tmp/chatgpt_reply.md
python3 automation/chatgpt_codex_loop.py show-codex-prompt --copy
python3 automation/chatgpt_codex_loop.py save-codex-reply --file /tmp/codex_reply.md
python3 automation/chatgpt_codex_loop.py status --verbose
```

Guidance helpers:

- `python3 automation/chatgpt_codex_loop.py guide` prints the next happy-path command to run based on the current loop state.
- `python3 automation/chatgpt_codex_loop.py cycle-example` prints one short full-cycle example with stdin, `--file`, and `--copy` usage.

Use them when:

- You want a quick reminder of the next manual step without inspecting `state.json`.
- You want a short copyable reference for the current command sequence.

Recommended daily usage:

```bash
python3 automation/chatgpt_codex_loop.py guide
python3 automation/chatgpt_codex_loop.py next-chatgpt --copy
python3 automation/chatgpt_codex_loop.py save-chatgpt-reply --file /tmp/chatgpt_reply.md
python3 automation/chatgpt_codex_loop.py show-codex-prompt --copy
python3 automation/chatgpt_codex_loop.py save-codex-reply --file /tmp/codex_reply.md
python3 automation/chatgpt_codex_loop.py guide
```
