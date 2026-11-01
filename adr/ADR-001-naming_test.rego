package adr001

import rego.v1

change(type, name, action) := {"resource_changes": [{
	"address": sprintf("%s.x", [type]),
	"type": type,
	"mode": "managed",
	"change": {"actions": [action], "after": {"name": name}},
}]}

test_good_resource_group if {
	count(deny) == 0 with input as change("azurerm_resource_group", "rg-payments-prod", "create")
}

test_good_storage_account if {
	count(deny) == 0 with input as change("azurerm_storage_account", "stpaymentsprod", "create")
}

test_wrong_prefix if {
	count(deny) == 1 with input as change("azurerm_resource_group", "payments-prod", "create")
}

test_missing_environment if {
	count(deny) == 1 with input as change("azurerm_virtual_network", "vnet-payments", "update")
}

test_uppercase if {
	count(deny) == 1 with input as change("azurerm_resource_group", "rg-Payments-prod", "create")
}

test_storage_hyphens if {
	count(deny) == 1 with input as change("azurerm_storage_account", "st-payments-prod", "create")
}

test_unlisted_type_is_ignored if {
	count(deny) == 0 with input as change("azurerm_subnet", "Anything", "create")
}

test_delete_is_ignored if {
	count(deny) == 0 with input as {"resource_changes": [{
		"address": "azurerm_resource_group.x",
		"type": "azurerm_resource_group",
		"mode": "managed",
		"change": {"actions": ["delete"], "after": null},
	}]}
}
