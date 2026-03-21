Review `automation/chatgpt_codex_loop.py` and implement the next safest high-value improvement: add a repository-local test/runtime override for the loop storage root so the CLI can run end-to-end safely against a temporary directory instead of always writing to `automation/loop/`.

Requirements:
- Keep the current command set and workflow intact.
- Preserve the default behavior exactly: if no override is provided, the tool must still use `automation/loop/` under the repository.
- Add one small override mechanism, preferably an environment variable such as `CHATGPT_CODEX_LOOP_DIR` or `CHATGPT_CODEX_LOOP_BASE`, that redirects:
  - `state.json`
  - `chatgpt/`
  - `codex/`
  - `prompts/`
- Keep the implementation stdlib-only and localized.
- Validate the override path clearly and fail with a helpful error if it is unusable.
- Update tests to cover the override behavior through the actual CLI entrypoint where practical, not only direct function calls.
- Add at least one focused end-to-end CLI test that runs a real cycle in a temporary directory:
  - `init`
  - `next-chatgpt`
  - `save-chatgpt-reply`
  - `show-codex-prompt`
  - `save-codex-reply`
- Keep edits minimal and consistent with the repository’s current style.
- After changes, run the relevant tests and summarize what changed, why, and the exact commands used to verify it.
