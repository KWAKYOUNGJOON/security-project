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
python3 automation/chatgpt_codex_loop.py next-chatgpt --copy
# paste the generated request into ChatGPT, then copy the full reply:
python3 automation/chatgpt_codex_loop.py save-chatgpt-reply --from-clipboard --copy-prompt
# paste that prompt into Codex, then copy the full reply:
python3 automation/chatgpt_codex_loop.py save-codex-reply --from-clipboard --next-chatgpt --copy
python3 automation/chatgpt_codex_loop.py status
```

Repeated-command variant:

```bash
python3 automation/chatgpt_codex_loop.py init --goal "Find the next safe repo improvement"
python3 automation/chatgpt_codex_loop.py advance --from-clipboard --copy
python3 automation/chatgpt_codex_loop.py advance --from-clipboard --copy
python3 automation/chatgpt_codex_loop.py advance --from-clipboard --copy
python3 automation/chatgpt_codex_loop.py status
```

Example:

```bash
python3 automation/chatgpt_codex_loop.py init --goal "Review automation/ and suggest the next safe improvement"
python3 automation/chatgpt_codex_loop.py next-chatgpt > /tmp/chatgpt_request.md
```

Convenience options:

- Use `save-chatgpt-reply --file <path>` to save a full ChatGPT reply from a file instead of piping stdin.
- Use `save-chatgpt-reply --from-clipboard` to save a full ChatGPT reply directly from the clipboard.
- Use `save-chatgpt-reply --copy-prompt` to immediately copy the extracted Codex prompt to the clipboard after saving it.
- Use `save-codex-reply --file <path>` to save a full Codex reply from a file instead of piping stdin.
- Use `save-codex-reply --from-clipboard` to save a full Codex reply directly from the clipboard.
- Use `save-codex-reply --next-chatgpt` to immediately prepare the next ChatGPT request after saving the Codex result.
- Use `save-codex-reply --next-chatgpt --copy` to also copy that newly created ChatGPT request to the clipboard.
- Use `advance` to perform the next happy-path loop action for the current phase without remembering which explicit command comes next.
- Use `next-chatgpt --copy` to print the generated request and also copy it to the system clipboard.
- Use `show-codex-prompt --copy` to print the latest extracted prompt and also copy it to the clipboard.
- Use `status --verbose` to show latest artifact paths plus short readable previews.

Example cycle with the convenience options:

```bash
python3 automation/chatgpt_codex_loop.py init --goal "Find the next safe automation improvement"
python3 automation/chatgpt_codex_loop.py next-chatgpt --copy
python3 automation/chatgpt_codex_loop.py save-chatgpt-reply --from-clipboard --copy-prompt
python3 automation/chatgpt_codex_loop.py save-codex-reply --from-clipboard --next-chatgpt --copy
python3 automation/chatgpt_codex_loop.py status --verbose
```

If you want to inspect or re-copy the saved prompt later, `show-codex-prompt --copy` still works unchanged.

If you want the lowest-friction repeated command in a clipboard-friendly environment, `advance --from-clipboard --copy` will generate the first request, then save the ChatGPT reply and copy the Codex prompt, then save the Codex reply and open the next cycle.

Wrapper-friendly JSON example:

```bash
python3 automation/chatgpt_codex_loop.py guide --json
python3 automation/chatgpt_codex_loop.py advance --from-clipboard --copy --json
```

Thin wrapper example:

```bash
python3 automation/chatgpt_codex_assist.py start --goal "Find the next safe repo improvement"
python3 automation/chatgpt_codex_assist.py step --from-clipboard
python3 automation/chatgpt_codex_assist.py step --from-clipboard
python3 automation/chatgpt_codex_assist.py status
```

`chatgpt_codex_assist.py` stays intentionally small. It calls the underlying loop CLI in `--json` mode so the common path is easier to drive without reimplementing loop-state rules.

VS Code usage:

- Open the Command Palette and run `Tasks: Run Task`.
- Choose `ChatGPT-Codex: Start Loop` and enter the goal when prompted.
- Use `ChatGPT-Codex: Advance From Clipboard` for the repeated happy path.
- Use `ChatGPT-Codex: Status`, `ChatGPT-Codex: Doctor`, `ChatGPT-Codex: History`, or `ChatGPT-Codex: Lock Status` when you want a quick check or recovery hint.

That task flow simply calls the same repo-local wrapper commands, so the existing loop numbering, guardrails, and clipboard behavior stay unchanged.

Troubleshooting via wrapper / VS Code tasks:

```bash
python3 automation/chatgpt_codex_assist.py history --limit 10
python3 automation/chatgpt_codex_assist.py lock-status
python3 automation/chatgpt_codex_assist.py doctor
```

In VS Code, the matching Command Palette tasks are `ChatGPT-Codex: History` and `ChatGPT-Codex: Lock Status`. If a lock looks suspicious and you need deeper manual recovery, use the lower-level loop CLI for the explicit `clear-lock --force` step.

Guidance helpers:

- `python3 automation/chatgpt_codex_loop.py guide` prints the next happy-path command to run based on the current loop state.
- `python3 automation/chatgpt_codex_loop.py history --limit 10` shows the most recent successful state-changing loop actions.
- `python3 automation/chatgpt_codex_loop.py cycle-example` prints one short full-cycle example with stdin, `--file`, and `--copy` usage.
- `python3 automation/chatgpt_codex_loop.py doctor` diagnoses loop-state inconsistencies and recommends the safest recovery step.

Use them when:

- You want a quick reminder of the next manual step without inspecting `state.json`.
- You want a short copyable reference for the current command sequence.

Recommended daily usage:

```bash
python3 automation/chatgpt_codex_loop.py guide
python3 automation/chatgpt_codex_loop.py advance --from-clipboard --copy
python3 automation/chatgpt_codex_loop.py advance --from-clipboard --copy
python3 automation/chatgpt_codex_loop.py advance --from-clipboard --copy
python3 automation/chatgpt_codex_loop.py guide
```

Troubleshooting example:

```bash
python3 automation/chatgpt_codex_loop.py lock-status
python3 automation/chatgpt_codex_loop.py doctor
python3 automation/chatgpt_codex_loop.py clear-lock --force
python3 automation/chatgpt_codex_loop.py history --limit 5
python3 automation/chatgpt_codex_loop.py reset-iteration 1
python3 automation/chatgpt_codex_loop.py doctor
```

Concurrent-use protection:

- State-changing loop commands now take a small repo-local write lock under the resolved loop root.
- If a second write command is started while another is still running, it will fail fast instead of interleaving state updates.
- Use `python3 automation/chatgpt_codex_loop.py lock-status` to inspect whether the current write lock looks active or suspicious before changing anything manually.
- Safest recovery step: wait and retry. If the lock keeps blocking progress and looks suspicious, run `python3 automation/chatgpt_codex_loop.py doctor` and only then use `python3 automation/chatgpt_codex_loop.py clear-lock --force` when you are sure no other loop command is active.
