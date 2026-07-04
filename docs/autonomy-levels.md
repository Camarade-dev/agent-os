# Autonomy levels

Autonomy levels describe how much an external agent may do before escalating to the owner. v0 records the level in `preflight.md` frontmatter as free text; enforcement is human-driven.

## Suggested levels

| Level | Meaning |
|-------|---------|
| L0 — Read only | Agent may inspect but not modify |
| L1 — Suggest | Agent proposes changes; owner applies |
| L2 — Local edit | Agent may edit within explicit file list |
| L3 — Bounded execute | Agent may run approved commands |
| L4 — Full delegate | Broad authority within stated scope |

## Gates

Autonomy gates are explicit checkpoints:

- scope expansion requires owner approval
- destructive commands require owner approval
- dependency or license changes require owner approval
- closure requires evidence + audit + owner decision

v0 does not automate gate enforcement. The protocol makes gates **visible and auditable**.
