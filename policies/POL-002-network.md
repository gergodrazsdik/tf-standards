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

No inbound rule may allow SSH (TCP port 22) or RDP (port 3389, TCP or UDP) from the internet.

A source counts as the internet when it's `*`, `0.0.0.0/0`, `::/0`, `Internet` or `Any`, in any case, or when it's any other public range wide enough to cover a large part of the internet, such as `0.0.0.0/1` or `128.0.0.0/2`. Private ranges such as `10.0.0.0/8` don't count. A rule covers a port when it names it, names a range holding it, or uses `*`. For SSH its protocol must also be `Tcp` or `*`, in any case, since SSH runs over TCP only; RDP counts over any protocol, as it uses UDP 3389 too. Reach these ports through a bastion or a private network instead.

## Enforcement

`POL-002-network.rego` checks standalone `azurerm_network_security_rule` resources and the `security_rule` blocks inside `azurerm_network_security_group`, including the plural `source_address_prefixes` and `destination_port_ranges` forms. A value only known after apply isn't judged. The policy only matches the exact forms listed above. Judging how much of the internet another range covers is left to review, so the reviewer's security agent is what catches those.
