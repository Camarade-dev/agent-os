# Manual agent workflow

This example shows how an owner uses Agent OS v0 CLI against any local project **without** an embedded agent runtime.

## 1. Bootstrap

```bash
cd /path/to/my-project
agent-os init
```

Creates `.agent-os/workspace.json` and `.agent-os/runs/`.

## 2. Open a run

```bash
agent-os mission
# => created run: 20260704-001
```

Edit the generated files under `.agent-os/runs/<run-id>/`.

## 3. Check gaps

```bash
agent-os status
```

Lists open runs and fields blocking closure.

## 4. Record audit

```bash
agent-os audit 20260704-001 --verdict pass --notes "Evidence matches mission."
```

## 5. Close (fail-closed)

```bash
agent-os close 20260704-001
```

Closure fails until mission, authority, evidence, audit verdict, owner decision, and closure verdict are all present.

## 6. Memory hygiene

After successful closure, complete `memory-update.md` manually.
