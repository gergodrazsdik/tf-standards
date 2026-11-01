---
id: POL-001
type: policy
status: accepted
applies_to:
  - azurerm_storage_account
severity: high
rego: POL-001-storage.rego
---

# POL-001: Storage account hardening

## Requirement

Every `azurerm_storage_account` must set:

| Attribute | Required value | Why |
| --- | --- | --- |
| `allow_nested_items_to_be_public` | `false` | No anonymous access to blobs |
| `https_traffic_only_enabled` | `true` | No unencrypted transport |
| `min_tls_version` | `TLS1_2` | No deprecated TLS versions |

## Enforcement

`POL-001-storage.rego` checks each setting on every plan. An attribute that's only known after apply counts as a violation, because the plan can't show it's safe.
