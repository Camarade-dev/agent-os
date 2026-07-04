# Toy run example

A minimal fictional run for documentation purposes. This is **not** a record of the Agent OS repository bootstrap itself.

## Run id

`20260704-001`

## Mission (filled)

Implement a `hello()` function that returns `"agent-os"` and document it in README.

## Preflight authority (filled)

```yaml
authority: owner
autonomy_level: L2
```

## Evidence (filled)

```text
$ python -c "from mypkg import hello; print(hello())"
agent-os
```

## Audit

```yaml
verdict: pass
```

## Owner decision

```yaml
decision: approve
```

## Closure

```yaml
verdict: CLOSED_SUCCESS
```

## Expected CLI flow

```bash
agent-os init .
agent-os mission .
agent-os status .
# fill artifacts...
agent-os audit 20260704-001 . --verdict pass
agent-os close 20260704-001 .   # fails until all fields filled
agent-os close 20260704-001 .   # succeeds when complete
```
