---
paths:
  - "**/*.rego"
---

# Rego

- Keep each policy next to its Markdown doc, with tests in `<doc>_test.rego`.
- Write tests for both the violating and the compliant case, and run them with `conftest verify`.
- Rules read plan JSON (`input.resource_changes`). Only judge `create` and `update` actions, and `managed` resources.
