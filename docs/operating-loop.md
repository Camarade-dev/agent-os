# Operating loop

The Agent OS operating loop is manual in v0. No agent runtime is embedded.

```
Owner defines mission
        │
        ▼
Preflight: authority + autonomy gates
        │
        ▼
Agent (external) executes within bounds
        │
        ▼
Evidence recorded
        │
        ▼
Audit reviews evidence
        │
        ▼
Owner decision
        │
        ▼
Closure (fail-closed)
        │
        ▼
Memory update
```

## CLI mapping

| Step | Command |
|------|---------|
| Bootstrap project | `agent-os init` |
| Open run | `agent-os mission` |
| Inspect gaps | `agent-os status` |
| Record audit | `agent-os audit <run-id> --verdict pass` |
| Close run | `agent-os close <run-id>` |

## Fail-closed closure

`agent-os close` refuses to mark a run closed until all required fields are present. This prevents silent acceptance of incomplete work.
