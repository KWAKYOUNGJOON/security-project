You are helping manage a manual ChatGPT <-> Codex loop for this repository.
Return exactly one next Codex prompt in the required format below.

Required response format:
## CODEX_PROMPT
<prompt>

## WHY
<brief rationale>

Constraints:
- Provide exactly one practical next Codex prompt.
- Keep the prompt repository-task oriented.
- Do not include extra sections before or after the required format.

Current completed iteration: 2
Next Codex cycle number: 3

## TOP_LEVEL_GOAL
security-project??automation/??寃?좏븯怨? ?꾩옱 援ъ“瑜??좎??섎㈃??媛???덉쟾???ㅼ쓬 媛쒖꽑 1媛쒕? 吏꾪뻾?쒕떎.

## LATEST_CHATGPT_REQUEST
You are helping manage a manual ChatGPT <-> Codex loop for this repository.
Return exactly one next Codex prompt in the required format below.

Required response format:
## CODEX_PROMPT
<prompt>

## WHY
<brief rationale>

Constraints:
- Provide exactly one practical next Codex prompt.
- Keep the prompt repository-task oriented.
- Do not include extra sections before or after the required format.

Current completed iteration: 2
Next Codex cycle number: 3

## TOP_LEVEL_GOAL
security-project??automation/??寃?좏븯怨? ?꾩옱 援ъ“瑜??좎??섎㈃??媛???덉쟾???ㅼ쓬 媛쒖꽑 1媛쒕? 吏꾪뻾?쒕떎.

## LATEST_CHATGPT_REQUEST
You are helping manage a manual ChatGPT <-> Codex loop for this repository.
Return exactly one next Codex prompt in the required format below.

Required response format:
## CODEX_PROMPT
<prompt>

## WHY
<brief rationale>

Constraints:
- Provide exactly one practical next Codex prompt.
- Keep the prompt repository-task oriented.
- Do not include extra sections before or after the required format.

Current completed iteration: 0
Next Codex cycle number: 1

## TOP_LEVEL_GOAL
security-project??automation/??寃?좏븯怨? ?꾩옱 援ъ“瑜??좎??섎㈃??媛???덉쟾???ㅼ쓬 媛쒖꽑 1媛쒕? 吏꾪뻾?쒕떎.

Focus on the single most useful next Codex step given the latest repository state.

## LATEST_CHATGPT_REPLY
## CODEX_PROMPT
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
- Keep edits minimal and consistent with the repository?셲 current style.
- After changes, run the relevant tests and summarize what changed, why, and the exact commands used to verify it.

## WHY
`automation/chatgpt_codex_loop.py` currently stores loop artifacts only under the repository-local `automation/loop/` path. Adding a small validated override is a safe, high-value improvement because it preserves the existing default workflow while making isolated dry runs and end-to-end CLI tests much safer and easier.

## LATEST_CODEX_REPLY
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
- Keep edits minimal and consistent with the repository???current style.
- After changes, run the relevant tests and summarize what changed, why, and the exact commands used to verify it.

Focus on the single most useful next Codex step given the latest repository state.

## LATEST_CHATGPT_REPLY
## CODEX_PROMPT
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
- Keep edits minimal and consistent with the repository?셲 current style.
- After changes, run the relevant tests and summarize what changed, why, and the exact commands used to verify it.

## WHY
`automation/chatgpt_codex_loop.py` currently stores loop artifacts only under the repository-local `automation/loop/` path. Adding a small validated override is a safe, high-value improvement because it preserves the existing default workflow while making isolated dry runs and end-to-end CLI tests much safer and easier.

## LATEST_CODEX_REPLY
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
- Keep edits minimal and consistent with the repository???current style.
- After changes, run the relevant tests and summarize what changed, why, and the exact commands used to verify it.

Focus on the single most useful next Codex step given the latest repository state.
