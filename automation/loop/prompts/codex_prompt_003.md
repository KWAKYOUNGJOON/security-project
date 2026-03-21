Review `automation/chatgpt_codex_loop.py` and implement the next safest high-value improvement: make `init` non-destructive by default so it refuses to overwrite an existing loop state unless the user explicitly opts in.

Requirements:
- Keep the current workflow intact for first-time setup.
- Preserve the default loop location and the existing `CHATGPT_CODEX_LOOP_DIR` override behavior.
- Add a small safety guard only: if the resolved loop root already contains `state.json` or existing loop artifacts, `init` should fail with a clear message instead of silently replacing state.
- If you need an escape hatch, add a minimal explicit override such as `init --force`, and keep it localized.
- Make the error/help text clear about which loop root is being protected.
- Keep the implementation stdlib-only and consistent with the current script style.
- Update tests to cover the protected default behavior and the explicit overwrite path through the CLI entrypoint where practical.
- Run the relevant tests after the change and summarize what changed, why, and the exact commands used to verify it.
