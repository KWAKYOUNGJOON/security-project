Implemented a small, localized override in [automation/chatgpt_codex_loop.py](/home/kyj/code/security-project/automation/chatgpt_codex_loop.py#L16). The CLI now honors `CHATGPT_CODEX_LOOP_DIR` as an alternate loop root for `state.json`, `chatgpt/`, `codex/`, and `prompts/`, while preserving the default behavior exactly when the variable is unset: it still uses `automation/loop/`. The override is validated up front and exits with a clear error if the target path is unusable.

Added subprocess-based CLI coverage in [automation/tests/test_chatgpt_codex_loop.py](/home/kyj/code/security-project/automation/tests/test_chatgpt_codex_loop.py#L16) so the real entrypoint is exercised end to end. The new tests cover:
- env override path resolution
- a full temporary-dir cycle: `init`, `next-chatgpt`, `save-chatgpt-reply`, `show-codex-prompt`, `save-codex-reply`
- a clear failure when `CHATGPT_CODEX_LOOP_DIR` points to a file

Also added a short usage note in [automation/README.md](/home/kyj/code/security-project/automation/README.md#L33).

Verified with:

```bash
python3 -m unittest automation.tests.test_chatgpt_codex_loop
python3 -m unittest discover -s automation/tests
```

Both passed:
- `automation.tests.test_chatgpt_codex_loop`: 23 tests
- `automation/tests` discovery: 34 tests