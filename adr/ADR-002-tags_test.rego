package adr002

import rego.v1

plan(after, unknown) := {"resource_changes": [{
	"address": "azurerm_resource_group.x",
	"type": "azurerm_resource_group",
	"mode": "managed",
	"change": {"actions": ["create"], "after": after, "after_unknown": unknown},
}]}

complete := {"owner": "platform", "environment": "prod", "project": "payments"}

test_all_tags_present if {
	count(deny) == 0 with input as plan({"tags": complete}, {})
}

test_one_tag_missing if {
	count(deny) == 1 with input as plan({"tags": {"owner": "platform", "environment": "prod"}}, {})
}

test_empty_value if {
	count(deny) == 1 with input as plan({"tags": object.union(complete, {"project": ""})}, {})
}

test_null_tags if {
	count(deny) == 3 with input as plan({"tags": null}, {})
}

test_no_tags_support_is_ignored if {
	count(deny) == 0 with input as plan({"name": "x"}, {})
}

test_unknown_value_is_accepted if {
	count(deny) == 0 with input as plan(
		{"tags": {"owner": "platform", "environment": "prod"}},
		{"tags": {"project": true}},
	)
}

test_delete_is_ignored if {
	count(deny) == 0 with input as {"resource_changes": [{
		"address": "azurerm_resource_group.x",
		"type": "azurerm_resource_group",
		"mode": "managed",
		"change": {"actions": ["delete"], "after": null, "after_unknown": {}},
	}]}
}

test_reports_the_attribute if {
	some result in deny with input as plan({"tags": null}, {})
	result.details.attribute == "tags"
}
