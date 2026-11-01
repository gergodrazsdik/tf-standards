---
id: ADR-002
type: adr
status: accepted
applies_to: ["*"]
severity: medium
rego: ADR-002-tags.rego
---

# ADR-002: Required tags

## Context

Tags are how costs get allocated and how an incident finds the team that owns a resource.

## Decision

Every resource that supports tags carries these three, with non-empty values:

| Tag | Meaning | Example |
| --- | --- | --- |
| `owner` | Team or person responsible | `platform-team` |
| `environment` | `dev`, `test` or `prod` | `prod` |
| `project` | Workload or repo the resource belongs to | `payments` |

## Consequences

Tags are checked on every plan by `ADR-002-tags.rego`. A resource counts as taggable when its planned values include a `tags` attribute, so no list of resource types has to be kept. Tag values only known after apply aren't checked.
