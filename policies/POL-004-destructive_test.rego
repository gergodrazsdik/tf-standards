package pol004

import rego.v1

plan(type, actions) := {"resource_changes": [{
	"address": sprintf("%s.x", [type]),
	"type": type,
	"mode": "managed",
	"change": {"actions": actions},
}]}

# C7.
test_replacing_a_database if {
	some result in deny with input as plan("azurerm_mssql_database", ["delete", "create"])
	contains(result.msg, "replaces")
	result.details.doc_id == "POL-004"
	result.details.severity == "high"
}

test_create_before_destroy_replacement if {
	count(deny) == 1 with input as plan("azurerm_mssql_database", ["create", "delete"])
}

test_deleting_a_database if {
	some result in deny with input as plan("azurerm_cosmosdb_account", ["delete"])
	contains(result.msg, "deletes")
}

test_every_listed_type if {
	every type in data_holding {
		count(deny) == 1 with input as plan(type, ["delete"])
	}
}

test_updating_is_fine if {
	count(deny) == 0 with input as plan("azurerm_mssql_database", ["update"])
}

test_creating_is_fine if {
	count(deny) == 0 with input as plan("azurerm_mssql_database", ["create"])
}

test_replacing_what_holds_no_data_is_fine if {
	count(deny) == 0 with input as plan("azurerm_virtual_network", ["delete", "create"])
}

test_a_data_source_isnt_judged if {
	input_plan := {"resource_changes": [{
		"address": "data.azurerm_mssql_database.x",
		"type": "azurerm_mssql_database",
		"mode": "data",
		"change": {"actions": ["delete"]},
	}]}
	count(deny) == 0 with input as input_plan
}
