# Memory hygiene

Agentic work generates noisy, stale, and contradictory context. Memory hygiene prevents ungoverned accumulation.

## Principles

1. **Retain** only decisions and facts that change future work.
2. **Revise** summaries when evidence supersedes earlier assumptions.
3. **Discard** transient logs, failed attempts, and out-of-scope digressions.
4. **Separate** run-local artifacts (under `.agent-os/runs/`) from project source.

## `memory-update.md`

After closure, the owner or agent records:

- what to keep in long-term project memory
- what to correct in docs or runbooks
- what to delete or stop repeating

## v0 scope

Agent OS v0 provides the `memory-update.md` template only. It does not implement vector stores, embeddings, or automatic summarization.
