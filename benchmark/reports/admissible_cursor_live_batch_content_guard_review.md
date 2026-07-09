# Admissible — Cursor Live Batch Content Guard Review

**Slice:** `ADMISSIBLE_EXECUTION_019_CONTENT_GUARD_FALSE_POSITIVES`
**Date:** 2026-07-09
**Mode:** offline fix + regression tests (no provider calls, no shell/npm/git/deploy/network execution, no commit)

## Observed live failure

During the live Cursor batch execution demo (slice 018 batch UX, following the
017 live structured-response retry), the flow worked end to end up through
explicit batch execution:

- Cursor wrote only `.admissible/agent-response.md`;
- exactly 3 `ADMISSIBLE_STRUCTURED_OPERATION` blocks were extracted;
- no target files existed before or after ingest;
- 3 admitted local file operations appeared in the "Ready to execute locally" panel;
- explicit batch execution ran.

Batch result was **partial success**, not 3/3:

| File | Result | Reason |
|---|---|---|
| `game.js` | succeeded | — |
| `index.html` | **failed** | `forbidden operation string in write content` |
| `style.css` | **failed** | `forbidden operation string in write content` |

## Root cause

`admissible/execution/bounded_local_executor.py`'s `_validate_operation_shape`
ran every `write_file.content` string through
`_looks_like_forbidden_natural_language()` — a flat regex scan for words like
`npm`, `git commit/push/...`, `deploy`, `shell`, `curl`, `ssh`, etc., with no
awareness of file type or execution context.

The goal prompt used in the demo explicitly told Cursor "No dependencies, no
shell commands, no git, no network, no deploy," and Cursor echoed that
constraint back as harmless human-readable text/comments inside the
generated `index.html` and `style.css` (e.g. "No npm, git, deploy, network,
or shell commands are required."). The naive scanner could not distinguish
that prose from an actual forbidden operation, so it refused two of the
three otherwise-safe local writes.

## Policy decision

Made the **content** guard for `write_file` path-aware and content-aware,
while leaving the **operation/category** guard (allowed operation names,
forbidden operation tokens, path traversal, absolute-path/symlink jail
checks) completely untouched.

New function `_forbidden_write_content_reason(path, content)` in
`admissible/execution/bounded_local_executor.py` replaces the flat scan for
`write_file.content` only:

| Extension | Policy |
|---|---|
| `.css` | Naive word scan **skipped** — prose/comments mentioning npm/git/deploy/network/shell are allowed. Refused only for an actual external network reference: a literal `http://`/`https://` substring anywhere in the content (covers `@import url("https://…")`, bare `@import "https://…"`, `url("https://…")`/`url(http://…)`, and any other literal external URL). Local relative references like `url("./sprite.png")` are unaffected and remain allowed. |
| `.js` | Naive word scan skipped; instead refused only for actual embedded network side effects: `fetch(`, `XMLHttpRequest`, `WebSocket(`, `EventSource(`, or a literal `http://`/`https://` substring. |
| `.html` / `.htm` | Naive word scan skipped; refused for the same network-side-effect patterns as `.js`, **plus** an external resource reference (`src="http(s)://…"` or `href="http(s)://…"`). |
| everything else (`.json`, `.yml`/`.yaml`, `.sh`, no extension, etc.) | **Unchanged** — keeps the original strict naive natural-language scan across the full forbidden-word list. |

**Follow-up correction (same day):** the initial version of this fix let `.css`
skip *all* content checks unconditionally. That was too permissive — a CSS
file can still declare a real external network dependency via `@import
url(...)`, bare `@import "..."`, or `url(...)` pointing at an `http(s)://`
resource. `.css` now reuses the same network-side-effect check as `.js`
(the existing `_has_network_side_effect()` helper, which already matches a
bare `http://`/`https://` substring) so all of those forms are refused,
while harmless prose/comments and local relative `url(...)` references
remain allowed.

The path-level check (`_looks_like_forbidden_natural_language(path)`, used
for both the file path string and to gate non-structured natural-language
tool/command strings) and the `_FORBIDDEN_OPERATION_TOKENS` operation-name
check are **unchanged** — these are what "operation/category guard remains
strict" refers to, and they were never the source of the false positive.

### Content guard policy before/after

**Before:**
```python
if _looks_like_forbidden_natural_language(content):
    raise BoundedExecutionError(
        "forbidden operation string in write content",
        diagnostic=DIAG_FORBIDDEN_OPERATION_CATEGORY,
    )
```
Applied identically to every `write_file` regardless of target path.

**After:**
```python
violation = _forbidden_write_content_reason(path, content)
if violation is not None:
    raise BoundedExecutionError(violation, diagnostic=DIAG_FORBIDDEN_OPERATION_CATEGORY)
```
`_forbidden_write_content_reason` branches on the target file's extension
(see table above) before deciding whether to run the naive scan or the
narrower network/external-resource checks.

Diagnostic code (`DIAG_FORBIDDEN_OPERATION_CATEGORY`) is unchanged in all
cases, so existing callers/UI that key off the diagnostic still work
unmodified; only the message text differs by refusal reason
(`forbidden operation string in write content` / `forbidden network call in
write content` / `forbidden external resource reference in write content`).

## Tests added

All added to `tests/test_admissible_bounded_local_executor.py` (no other
test files modified):

**`TestBoundedExecutorContentGuardFalsePositives`** (unit-level, direct
`execute_bounded_local_action` calls):
- `test_html_harmless_forbidden_words_succeeds` — `index.html` containing "No npm, git, deploy, network, or shell commands are required." now writes successfully.
- `test_css_comment_harmless_forbidden_words_succeeds` — `style.css` comment with the same harmless words now writes successfully.
- `test_css_import_url_external_refused` — `style.css` with `@import url("https://example.com/x.css")` is refused.
- `test_css_bare_import_external_refused` — `style.css` with bare `@import "https://example.com/x.css"` is refused.
- `test_css_background_image_url_external_refused` — `style.css` with `background-image: url("https://example.com/bg.png")` is refused.
- `test_css_bare_http_url_external_refused` — `style.css` with a bare literal `http://` URL in a comment is refused.
- `test_css_local_relative_url_allowed` — `style.css` with a local relative `url("./sprite.png")` reference still writes successfully.
- `test_simple_local_game_js_succeeds` — plain local `game.js` canvas loop writes successfully.
- `test_js_fetch_network_call_refused` — `game.js` containing `fetch("https://example.com")` is refused, file not written.
- `test_html_external_script_src_refused` — `index.html` with `<script src="https://cdn.example.com/lib.js">` is refused.
- `test_package_json_npm_scripts_refused` — `package.json` with an `npm run build` script is refused (unchanged policy, `.json` keeps the naive scan).
- `test_deploy_workflow_yaml_refused` — `.github/workflows/deploy.yml`-style content is refused (the `deploy` token in the *path* alone already trips the existing path check; content would also trip the naive scan for non-safe extensions).

**`TestBoundedExecutorControlSurface` (extended)**:
- `test_batch_execution_with_harmless_forbidden_words_succeeds_three_of_three` — three separately-admitted `create_file` actions (`index.html`, `style.css`, `game.js`), each containing the harmless "no npm/git/deploy/network/shell" phrasing, batch-execute 3/3 via `execute_bounded_local_batch`.

**`TestBoundedExecutorLiveContentGuardRegression`** (end-to-end, reproduces the actual live scenario via `ingest_agent_response` + `execute_bounded_local_batch`, not just direct executor calls):
- `test_ingest_does_not_auto_execute` — ingesting the 3-block structured response (content echoing the goal's own no-npm/git/deploy/network/shell phrasing) writes no files and leaves all 3 actions eligible with no diagnostic; `side_effect_executed_by_admissible` stays `False`.
- `test_batch_execution_succeeds_three_of_three_after_content_guard_fix` — explicit batch execution after ingest now reports `succeeded_count: 3`, `failed_count: 0`, and all three files exist.

The existing `TestBoundedExecutorBoundary.test_no_agent_os_imports_in_admissible_modules` test (unchanged) already covers the new code — no `agent_os` import was introduced.

## Remaining limits

- The network-side-effect check for `.js`/`.html`/`.css` uses a bare `https?://` substring match. A file of any of these types with a harmless prose/comment mention of a URL (e.g. "see https://example.com for docs") would still be refused — this mirrors the explicit requirement (literal `http://`/`https://` must be refused for CSS, and "literal external http:// / https:// dependencies" for JS) but is itself a narrower version of the same prose-vs-code ambiguity that caused the original bug. `test_css_bare_http_url_external_refused` confirms and locks in this exact behavior for CSS per explicit instruction. Not otherwise exercised by any live scenario so far.
- Extensions outside `.html`/`.htm`/`.css`/`.js` (e.g. `.json`, `.yml`, `.md`, `.sh`) keep the original flat naive-word scan, so a harmless prose file with one of those extensions that happens to mention "npm" or "deploy" could still false-positive. This was intentionally left narrow (unchanged behavior) rather than broadened, since no live failure has been observed for those extensions and widening the safe list further wasn't requested.
- There is no extension-based blocklist for shell-script-like paths (`.sh`, `.ps1`, `.bat`, etc.) independent of content — a shell script with no forbidden words in its body would not be refused by this guard. This wasn't part of the observed failure and no test in this slice exercises it; flagged here as a gap for a future slice if it becomes a real scenario.
- Only `write_file` content is affected; `read_file`/`list_files` and the operation/category/path guards are untouched, so this fix is scoped exactly to the reported false positive.

## Whether live retry is needed

**Not required to validate the fix** — the new `TestBoundedExecutorLiveContentGuardRegression` class reproduces the exact reported scenario (ingest of a 3-block structured response whose `index.html`/`style.css`/`game.js` content echoes the goal's own "no npm/git/deploy/network/shell" phrasing, then explicit batch execution) entirely offline and passes 3/3.

A live Cursor retry would still be valuable as a **product-readiness confirmation** (matching the human-in-the-loop demo flow exactly, including real Cursor phrasing rather than the synthetic regression text), but is not needed to confirm the bug is fixed — the offline regression tests cover the reported failure mode directly.

## Diagnostics run

| Command | Result |
|---|---|
| `git status` | 2 files modified: `admissible/execution/bounded_local_executor.py`, `tests/test_admissible_bounded_local_executor.py` |
| `python -m pytest tests/test_admissible_bounded_local_executor.py -q` | **36 passed** (21 pre-existing + 10 initial fix + 5 CSS follow-up) |
| `python -m pytest tests/test_admissible_execution_review_ux.py -q` | **17 passed** |
| `python -m pytest tests/test_admissible_tiny_local_game_dynamic_run.py -q` | **11 passed** |
| `python -m pytest tests/test_admissible_control_surface_live_dynamic_run_rehearsal.py -q` | **2 passed** |
| `python -m pytest tests/ -k admissible -q` | **834 passed**, 1258 deselected, 156 subtests passed |

## Files changed

| File | Change |
|---|---|
| `admissible/execution/bounded_local_executor.py` | Replaced the flat `write_file.content` naive-word scan with path-aware `_forbidden_write_content_reason()`; added `_has_network_side_effect()` / `_has_external_resource_reference()` helpers and their patterns. `.css` reuses `_has_network_side_effect()` to refuse external `@import`/`url()` references while still allowing harmless prose and local relative `url()` paths. Operation/category/path guards untouched. |
| `tests/test_admissible_bounded_local_executor.py` | Added `TestBoundedExecutorContentGuardFalsePositives` (12 tests, incl. 5 CSS external-reference tests), one batch test on `TestBoundedExecutorControlSurface`, and `TestBoundedExecutorLiveContentGuardRegression` (2 tests) — 15 new tests total. |
| `benchmark/reports/admissible_cursor_live_batch_content_guard_review.md` | **added** — this report. |

No product code outside `admissible/execution/bounded_local_executor.py` was touched. No commit made (per slice constraints).

## Constraints exercised

- No provider (Cursor/Claude/OpenAI/Gemini) API calls
- No shell/npm/git/deploy/network execution
- No new executor operation capabilities (`ALLOWED_BOUNDED_OPERATIONS` unchanged)
- No admission gate weakened (`_FORBIDDEN_OPERATION_TOKENS`, path traversal/absolute/symlink checks, decision-label eligibility rules all unchanged)
- No auto-execution on ingest (verified by new regression test)
- No mutation of original decisions (unaffected by this change; pre-existing immutability tests still pass)
- No `agent_os` import introduced (verified by existing boundary test)
- No commit created
