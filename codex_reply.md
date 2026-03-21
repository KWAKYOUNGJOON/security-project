Made a small UX-only change in [automation/chatgpt_codex_loop.py](/home/kyj/code/security-project/automation/chatgpt_codex_loop.py#L259): `status` and `guide` now print the resolved loop root first, labeled as either `default repository path` or `override via CHATGPT_CODEX_LOOP_DIR`. That keeps the command set and workflow unchanged while making it obvious at a glance whether the CLI is using `automation/loop/` or a temporary override. The status path wiring was updated at [automation/chatgpt_codex_loop.py](/home/kyj/code/security-project/automation/chatgpt_codex_loop.py#L268) and [automation/chatgpt_codex_loop.py](/home/kyj/code/security-project/automation/chatgpt_codex_loop.py#L315).

Updated tests in [automation/tests/test_chatgpt_codex_loop.py](/home/kyj/code/security-project/automation/tests/test_chatgpt_codex_loop.py#L65) and [automation/tests/test_chatgpt_codex_loop.py](/home/kyj/code/security-project/automation/tests/test_chatgpt_codex_loop.py#L300) so existing guide/status coverage expects the root line, and added CLI-entrypoint checks for both default and override-root output at [automation/tests/test_chatgpt_codex_loop.py](/home/kyj/code/security-project/automation/tests/test_chatgpt_codex_loop.py#L457). The earlier end-to-end override cycle coverage remains intact.

Verified with:

```bash
python3 -m unittest automation.tests.test_chatgpt_codex_loop
python3 -m unittest discover -s automation/tests
```

Both passed:
- `automation.tests.test_chatgpt_codex_loop`: 25 tests
- `automation/tests` discovery: 36 tests