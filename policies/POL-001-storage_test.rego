package pol001

import rego.v1

plan(after) := {"resource_changes": [{
	"address": "azurerm_storage_account.x",
	"type": "azurerm_storage_account",
	"mode": "managed",
	"change": {"actions": ["create"], "after": after},
}]}

good := {
	"allow_nested_items_to_be_public": false,
	"https_traffic_only_enabled": true,
	"min_tls_version": "TLS1_2",
}

test_compliant if {
	count(deny) == 0 with input as plan(good)
}

test_public_blobs if {
	count(deny) == 1 with input as plan(object.union(good, {"allow_nested_items_to_be_public": true}))
}

test_http_allowed if {
	count(deny) == 1 with input as plan(object.union(good, {"https_traffic_only_enabled": false}))
}

test_old_tls if {
	count(deny) == 1 with input as plan(object.union(good, {"min_tls_version": "TLS1_0"}))
}

test_unknown_attribute_is_a_violation if {
	count(deny) == 3 with input as plan({})
}

test_other_type_is_ignored if {
	count(deny) == 0 with input as {"resource_changes": [{
		"address": "azurerm_resource_group.x",
		"type": "azurerm_resource_group",
		"mode": "managed",
		"change": {"actions": ["create"], "after": {}},
	}]}
}

test_reports_the_attribute if {
	some result in deny with input as plan(object.remove(good, ["min_tls_version"]))
	result.details.attribute == "min_tls_version"
}
