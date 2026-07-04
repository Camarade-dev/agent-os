# Dogfood 003 - local-site-audit

Formal synthesis for the third Agent OS v0 dogfood run. This run tested Agent OS against a medium-risk local site audit CLI while keeping the Agent OS core repository frozen.

## Project and run

Project name:

```
agent-os-dogfood-local-site-audit
```

Canonical dogfood project location:

```
../agent-os-dogfood-local-site-audit/
```

Agent OS core was frozen at commit:

```
473323780ca35e3201088048879e0efc60a99257
```

Final dogfood status:

```
DOGFOOD_CLOSED_SUCCESS
```

The dogfood project was a sibling of the Agent OS core repository. The core `agent-os/` repository was not the implementation target and did not receive a `.agent-os/` workspace at its root.

## What was tested

Dogfood 003 tested a local-only Python CLI that audits a local folder of HTML and Markdown files. The CLI was scoped to filesystem inspection only.

The run exercised:

- audit of a local HTML/Markdown folder;
- detection of missing HTML titles and page H1s;
- detection of broken local links;
- detection of missing local images;
- generation of `report.md`;
- generation of `report.json`;
- project tests for the dogfood CLI;
- Agent OS fail-closed lifecycle from workspace initialization through closure.

The run did not test web crawling, HTTP fetching, Lighthouse, scoring, dashboards, plugins, orchestration, cloud features, SaaS behavior, APIs, LLM calls, or guided fill.

## Scope risk

Dogfood 003 was a better dogfood than Dogfood 001 because the local-site-audit problem naturally creates product and implementation pressure. A site audit can easily expand from local file inspection into crawling, HTTP checks, browser automation, Lighthouse-style diagnostics, SEO scoring, dashboards, plugin systems, link ranking, or hosted reports.

Agent OS helped keep those expansions excluded. The mission, preflight boundaries, evidence requirements, audit, owner decision, and closure gate made the permitted surface explicit: local files in, local reports out, tests as evidence, no Agent OS core changes, and no new product surface.

This made the run more representative than Dogfood 001. The work still remained local and bounded, but it had enough natural scope pressure to test whether Agent OS could keep a delegated implementation from growing beyond the authorized slice.

## Agent OS evidence

The run recorded the following Agent OS evidence:

- `.agent-os/` was initialized in the sibling project, not in the Agent OS core repository.
- Fail-closed closure was demonstrated before completion.
- Closure validation eventually returned `True []`.
- The run closed successfully as `DOGFOOD_CLOSED_SUCCESS`.
- Agent OS core `git status` and `git diff` remained clean during the dogfood run.

The clean-core evidence is important because Dogfood 003 was meant to test Agent OS as a frozen protocol, not to use the dogfood pressure as a reason to change CLI or validation behavior.

## Parallel shell and re-close lesson

One close attempt succeeded and moved the run to a closed state. A later parallel or retried shell attempted to close the same run again and returned exit code 1 with:

```
run is already closed
```

That result was benign. It showed the already-closed guard working after the first closure had succeeded.

The reporting lesson is that a close command returning exit code 1 is not always equivalent to "closure failed." Reports should distinguish:

- closure failed because required fields still block closure;
- closure already completed and a later close attempt hit the closed-run guard.

Dogfood 003 does not authorize changing close semantics or making re-close idempotent. It only records the reporting distinction as a lesson.

## Usefulness assessment

Agent OS helped with this run.

It prevented scope creep by keeping crawling, HTTP, UI, Lighthouse-style checks, scoring, dashboards, plugins, and orchestration outside the authorized work. It preserved the frozen Agent OS core by making the dogfood project the only implementation target. It clarified evidence requirements by forcing the run to record tests, reports, closure validation, and owner acceptance before closure. It made closure more trustworthy because the run could not close until required artifacts were complete.

The run also exposed friction. Evidence capture remained manual, command outputs had to be reported deliberately, and concurrent shell reporting created ambiguity after one close had already succeeded. These are real usability issues, but they are not enough by themselves to justify changing Agent OS v0 behavior inside this synthesis.

## Feature pressure parked

The following feature pressure is explicitly parked:

- automatic evidence capture;
- command transcript capture;
- re-close idempotency changes;
- dashboards;
- orchestration.

None of these should be implemented from Dogfood 003 alone. Each would require a separate design decision because each changes Agent OS from a minimal local protocol toward runtime behavior, product surface, or coordination machinery.

## Conclusion

Dogfood 003 strengthens the case for Agent OS on medium-risk delegated work. Compared with Dogfood 001, the local-site-audit CLI had more natural scope pressure and more meaningful evidence needs, and Agent OS helped keep the work bounded, reviewable, and closed under explicit gates.

The run does not yet justify implementing evidence automation. Manual evidence capture and concurrent shell reporting are documented residual debt, but evidence automation should wait for a separate design decision rather than being smuggled in through a dogfood synthesis.
