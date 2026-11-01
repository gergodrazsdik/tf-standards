---
paths:
  - "**/*.rego"
---

# Rego

- Keep each policy next to its Markdown doc, with tests in `<doc>_test.rego`.
- Write tests for both the violating and the compliant case, and run them with `conftest verify`.
- `conftest verify` doesn't run the policies the way a review does. `conftest test` queries every rule whose name starts with `deny`, `violation` or `warn`, and fails on a helper function named like that, so `just policy-test` runs it too.
- Rules read plan JSON (`input.resource_changes`). Only judge `create` and `update` actions, and `managed` resources.
