Review `automation/chatgpt_codex_loop.py` and implement the next safest high-value improvement: make the active loop storage root visible in the CLI so operators can immediately tell whether they are using the default `automation/loop/` location or an override from `CHATGPT_CODEX_LOOP_DIR`.

Requirements:
- Keep the current command set and workflow intact.
- Preserve default behavior exactly when no override is set.
- Add a small, localized UX improvement only: surface the resolved loop root in the most relevant command output, preferably `status` and/or `guide`, without changing the core file layout or iteration flow.
- Make the output clear enough that a user can distinguish default-path runs from temporary-directory runs at a glance.
- Keep the implementation stdlib-only and consistent with the current script style.
- Update tests to cover both the default-root and override-root output through the CLI entrypoint where practical.
- Keep edits minimal and run the relevant tests after the change.
