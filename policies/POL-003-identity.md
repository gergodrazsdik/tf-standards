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

`POL-003-identity.rego` checks `role_definition_name` and `scope` on every plan. It can't judge an assignment that names its role by `role_definition_id`, because the reviewer removes GUIDs from plans before policies see them, and the role's name isn't there. Use `role_definition_name`, so that this policy can read it. A value only known after apply isn't judged.
