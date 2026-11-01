---
id: ADR-003
type: adr
status: accepted
applies_to: ["*"]
topics: [cost]
severity: medium
---

# ADR-003: Large cost increases get a second look

## Context

A size or SKU change can add a large monthly cost in one line, and it's easy to miss in a review. Most increases are fine, so this asks for attention rather than forbidding anything.

## Decision

Flag a change when, at list prices and without usage-based charges, it does either of these to one resource:

| Rule | Example |
| --- | --- |
| Adds more than $50 a month | $31.90 to $141.70 |
| Goes up by more than half, and adds at least $10 a month | $20.00 to $35.00 |

A new resource counts as an increase from $0. A saving or a smaller increase isn't flagged.

## Consequences

The flag asks the author to confirm the increase is intended, and never blocks. There's no Rego for this, because a policy only sees the plan and not its prices: the reviewer's cost agent applies it to Infracost's figures. A resource Infracost couldn't price isn't judged.
