---
id: ADR-001
type: adr
status: accepted
applies_to:
  - azurerm_resource_group
  - azurerm_storage_account
  - azurerm_virtual_network
  - azurerm_user_assigned_identity
severity: low
rego: ADR-001-naming.rego
---

# ADR-001: Resource naming

## Context

Consistent names show what a resource is, which workload owns it and which environment it serves, without opening the portal.

## Decision

Names follow `<prefix>-<workload>-<environment>`, in lowercase:

| Resource type | Prefix | Example |
| --- | --- | --- |
| `azurerm_resource_group` | `rg` | `rg-payments-prod` |
| `azurerm_virtual_network` | `vnet` | `vnet-payments-prod` |
| `azurerm_user_assigned_identity` | `id` | `id-payments-apply-prod` |
| `azurerm_storage_account` | `st` | `stpaymentsprod` |

- `<workload>` is lowercase letters and digits, optionally split by hyphens.
- `<environment>` is `dev`, `test` or `prod`.
- Storage account names allow no hyphens, so the parts are joined directly, within Azure's limit of 24 characters.

## Consequences

Names are checked on every plan by `ADR-001-naming.rego`. Resource types outside the table aren't checked yet; add a row and a prefix to extend it.
