# Admissible Build Week demo surface

`admissible/build_week_demo.py` renders one polished, self-contained,
read-only HTML replay of the frozen canonical native canary
(`native-cursor-canary-004`) for the OpenAI Build Week video. It is a
presentation artifact generator, not a dashboard and not a new protocol
layer: the generated page is never execution evidence and never an authority
record.

## Generation

```
python -m admissible.build_week_demo ^
  --run-root "C:\Users\stris\Documents\Projets\ENTRE\native-cursor-canary-004" ^
  --output "C:\Users\stris\Documents\Projets\ENTRE\admissible-build-week-demo\index.html"
```

- `--run-root` (required): the immutable canary run root, read-only.
- `--output` (required): the HTML destination; it must live outside the run
  root. The output file is the only path the generator writes (its parent
  directory is created when missing).
- `--open` (optional): after a successful generation, open the page with
  Python's standard `webbrowser` module. No server is involved; the page is
  a plain local file.

On success the CLI prints the output path, the byte size, and the SHA-256 of
the generated file, and exits `0`.

## Evidence-only, read-only guarantees

Every displayed fact is resolved through the committed read-only protocol
surfaces:

- execution success through `reconstruct_completed_canary_success`, the
  evidence-only reconstruction that can veto but never grant execution;
- the committed review through `classify_native_checkpoint_review_binding`
  and its full loader;
- human acceptance through `classify_native_checkpoint_acceptance` and its
  full loader;
- run identity through the fingerprint-validated persisted authorization
  payload;
- archive absence by enumerating the persisted record inventory and proving
  no archive record kind exists (the frozen protocol defines none).

The generator never invokes Cursor, a provider, npm, a native process, the
behavioral verifier, or checkpoint capture; it never reserves an attempt,
writes a review binding or acceptance, transitions delegated state, touches
the network, or alters Git configuration. A process-local, non-persisted Git
`safe.directory` environment overlay is applied only when the sandbox
process identity cannot otherwise perform the committed read-only evidence
reconstruction; nothing is written to any Git configuration file.

Statuses are never derived from filename presence, substring matching, or
trusted JSON fields, and are never copied from a prompt or hardcoded: if any
required fact fails to load, validate, or classify, no success page is
produced.

## Output determinism

The same immutable run evidence and the same committed source produce
byte-identical output: UTF-8, exactly one terminal newline, deterministic
ordering, correct HTML escaping, no external asset, CDN, font, script, or
network request. The page contains no generation wall-clock time, random
value, environment value, or absolute local path — only persisted
timestamps. Generation fails closed if any fact routed to the page carries
an absolute local path.

## Expected canonical state

The canonical run must independently resolve to exactly:

| Fact             | Value                                |
| ---------------- | ------------------------------------ |
| Execution        | `CHECKPOINT_CAPTURED_CANARY_SUCCESS` |
| Review binding   | `PRESENT_VALID`                      |
| Human acceptance | `PRESENT_VALID`                      |
| Archive          | `ABSENT`                             |

Archive absence is intentional and is rendered as a deliberate boundary, not
an error. Review binding and human acceptance are displayed as two separate
facts and are never collapsed.

## What the viewer does not do

The generated page is inert: static HTML with self-contained CSS and a small
vanilla-JavaScript presentation control. It performs no request, stores no
state, reruns nothing, and grants nothing. Viewing it asserts no authority:
no model invocation, retry, repair, continuation, checkpoint rerun,
deployment, archive, or push is authorized by the page or by generating it.

## Video-oriented navigation

A "Guided replay" control (bottom-right, JavaScript-only) walks five steps:

1. Mission
2. Native execution
3. Evidence and checkpoint
4. Review and human acceptance
5. Authority boundary

Previous/next controls scroll to and highlight existing sections only; the
Escape key exits the guided highlighting. There is no automatic timed
animation, and the page remains fully understandable without JavaScript.

## Troubleshooting invalid or missing evidence

When the run root is missing, incomplete, tampered with, or resolves to any
state other than the canonical one above, the CLI prints the blocking reason
to stderr (with run-root paths redacted), writes a clearly status-free
validation-error page when the output path is usable, and exits non-zero.
The error page claims no execution, review, acceptance, or archive status.
Common causes:

- the run root does not contain the `evidence/` and `work/` layout of the
  canonical run (the generator never creates run-root state);
- the output path lies beneath the run root (always refused);
- a lifecycle, review-binding, or acceptance record fails canonical-bytes,
  fingerprint, or cross-binding validation;
- Git refuses the immutable workspace under the current process identity and
  the `safe.directory` overlay condition does not apply.

## Protocol freeze boundary

The protocol is frozen under `PROTOCOL_FREEZE_FOR_BUILD_WEEK_DEMO`. This
surface only adds `admissible/build_week_demo.py`,
`tests/test_admissible_build_week_demo.py`, and this document; no protocol,
executor, reducer, evidence, durability, review, acceptance, or archive
module is modified. The focused test suite covers only the demo generator
and does not duplicate the frozen protocol test matrix.
