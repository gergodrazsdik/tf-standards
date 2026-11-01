---
id: POL-002
type: policy
status: accepted
applies_to:
  - azurerm_network_security_group
  - azurerm_network_security_rule
topics: [network, security]
severity: high
rego: POL-002-network.rego
---

# POL-002: No admin ports open to the internet

## Requirement

No inbound rule may allow SSH (port 22) or RDP (port 3389) from the internet.

A source counts as the internet when it's `*`, `0.0.0.0/0`, `::/0`, `Internet` or `Any`, in any case. A rule covers a port when it names it, names a range holding it, or uses `*`. Reach these ports through a bastion or a private network instead.

## Enforcement

`POL-002-network.rego` checks standalone `azurerm_network_security_rule` resources and the `security_rule` blocks inside `azurerm_network_security_group`, including the plural `source_address_prefixes` and `destination_port_ranges` forms. A value only known after apply isn't judged.
