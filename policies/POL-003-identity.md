---
id: POL-003
type: policy
status: accepted
applies_to:
  - azurerm_role_assignment
topics: [security]
severity: high
rego: POL-003-identity.rego
---

# POL-003: No broad roles at subscription scope

## Requirement

An `azurerm_role_assignment` must not grant `Owner` or `User Access Administrator` at the scope of a whole subscription or wider. Both can hand out further access, so they turn one identity's compromise into control of everything under that scope. Grant them on a resource group or a resource, or use a narrower role.

## Enforcement

`POL-003-identity.rego` checks the role and `scope` on every plan. It reads the role from `role_definition_name`, or from `role_definition_id` when that holds the built-in Owner or User Access Administrator role definition ID (`8e3af657-a8ff-443c-a75c-2fe8c4bcb635`, `18d7d88d-d35e-4fb5-a5c3-7773c4a72b09`) after any scope prefix, such as `/subscriptions/<id>/providers/Microsoft.Authorization/roleDefinitions/<id>` or the bare `/providers/...` form. Built-in role IDs are the same in every tenant, so the reviewer keeps them when it removes GUIDs from plans. A custom role's ID is removed, so the policy can't judge a custom role named by ID. A value only known after apply isn't judged.
