# Primitives

Agent OS v0 defines seven run artifacts, each backed by a template under `agent_os/templates/`.

| Artifact | Role |
|----------|------|
| `mission.md` | Objective, scope, and success criteria |
| `preflight.md` | Authority, autonomy gates, context boundaries |
| `evidence.md` | Commands, outputs, and observations |
| `audit.md` | Independent review verdict |
| `owner-decision.md` | Owner acceptance or rejection |
| `closure.md` | Final run disposition |
| `memory-update.md` | Post-closure memory hygiene |

## Workspace layout

When `agent-os init` runs in a project:

```
.agent-os/
  workspace.json
  runs/
    <run-id>/
      run.json
      mission.md
      preflight.md
      evidence.md
      audit.md
      owner-decision.md
      closure.md
      memory-update.md
```

## Placeholder discipline

Templates ship with `PLACEHOLDER` values. Closure validation treats placeholders and empty fields as missing. The protocol **fails closed**: incomplete runs cannot close.

## Required for closure

- mission content present
- authority set in `preflight.md` frontmatter
- evidence body present
- audit verdict set
- owner decision set
- closure verdict set
