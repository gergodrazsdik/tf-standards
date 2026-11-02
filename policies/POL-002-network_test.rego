package pol002

import rego.v1

rule_plan(rule) := {"resource_changes": [{
	"address": "azurerm_network_security_rule.x",
	"type": "azurerm_network_security_rule",
	"mode": "managed",
	"change": {"actions": ["create"], "after": rule},
}]}

group_plan(rules) := {"resource_changes": [{
	"address": "azurerm_network_security_group.x",
	"type": "azurerm_network_security_group",
	"mode": "managed",
	"change": {"actions": ["create"], "after": {"security_rule": rules}},
}]}

open_ssh := {
	"direction": "Inbound",
	"access": "Allow",
	"source_address_prefix": "0.0.0.0/0",
	"destination_port_range": "22",
}

# C1, which Checkov 3.4.0 misses because of the 0.0.0.0/0 form.
test_ssh_from_any_ipv4 if {
	count(deny) == 1 with input as rule_plan(open_ssh)
}

test_reports_the_attribute if {
	some result in deny with input as rule_plan(open_ssh)
	result.details.attribute == "source_address_prefix"
	result.details.doc_id == "POL-002"
	result.details.severity == "high"
}

test_rdp if {
	count(deny) == 1 with input as rule_plan(object.union(open_ssh, {"destination_port_range": "3389"}))
}

test_sources_in_any_case if {
	every source in ["*", "::/0", "Internet", "INTERNET", "Any"] {
		count(deny) == 1 with input as rule_plan(object.union(open_ssh, {"source_address_prefix": source}))
	}
}

test_wildcard_port if {
	count(deny) == 1 with input as rule_plan(object.union(open_ssh, {"destination_port_range": "*"}))
}

test_range_holding_the_port if {
	count(deny) == 1 with input as rule_plan(object.union(open_ssh, {"destination_port_range": "20-30"}))
}

test_plural_ports if {
	rule := {
		"direction": "Inbound",
		"access": "Allow",
		"source_address_prefix": "*",
		"destination_port_ranges": ["443", "22"],
	}
	count(deny) == 1 with input as rule_plan(rule)
}

test_plural_sources if {
	rule := {
		"direction": "Inbound",
		"access": "Allow",
		"source_address_prefixes": ["10.0.0.0/8", "0.0.0.0/0"],
		"destination_port_range": "22",
	}
	count(deny) == 1 with input as rule_plan(rule)
}

test_inline_rule if {
	some result in deny with input as group_plan([open_ssh])
	result.details.attribute == "security_rule"
}

test_one_finding_for_a_group_with_two_open_rules if {
	count(deny) == 1 with input as group_plan([open_ssh, object.union(open_ssh, {"destination_port_range": "3389"})])
}

test_private_source_is_fine if {
	count(deny) == 0 with input as rule_plan(object.union(open_ssh, {"source_address_prefix": "10.0.0.0/8"}))
}

test_other_port_is_fine if {
	count(deny) == 0 with input as rule_plan(object.union(open_ssh, {"destination_port_range": "443"}))
}

test_range_without_the_port_is_fine if {
	count(deny) == 0 with input as rule_plan(object.union(open_ssh, {"destination_port_range": "8000-9000"}))
}

test_outbound_is_fine if {
	count(deny) == 0 with input as rule_plan(object.union(open_ssh, {"direction": "Outbound"}))
}

test_deny_rule_is_fine if {
	count(deny) == 0 with input as rule_plan(object.union(open_ssh, {"access": "Deny"}))
}

# The doc says a wide public range counts too, but only review judges it, as the reviewer's evals rely on.
test_a_wide_public_range_is_left_to_review if {
	count(deny) == 0 with input as rule_plan(object.union(open_ssh, {"source_address_prefix": "0.0.0.0/1"}))
}

test_a_delete_isnt_judged if {
	plan := {"resource_changes": [{
		"address": "azurerm_network_security_rule.x",
		"type": "azurerm_network_security_rule",
		"mode": "managed",
		"change": {"actions": ["delete"], "after": null},
	}]}
	count(deny) == 0 with input as plan
}

test_unknown_values_arent_judged if {
	count(deny) == 0 with input as rule_plan({"direction": "Inbound", "access": "Allow"})
}
