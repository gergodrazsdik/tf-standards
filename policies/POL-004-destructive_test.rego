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

test_data_stores_inside_a_server_or_account if {
	every type in [
		"azurerm_mssql_managed_database",
		"azurerm_postgresql_flexible_server_database",
		"azurerm_mysql_flexible_database",
		"azurerm_cosmosdb_sql_container",
		"azurerm_storage_container",
		"azurerm_storage_share",
		"azurerm_key_vault_secret",
	] {
		count(deny) == 1 with input as plan(type, ["delete", "create"])
	}
}

test_replacing_a_disk_or_cache if {
	every type in ["azurerm_managed_disk", "azurerm_redis_cache"] {
		count(deny) == 1 with input as plan(type, ["delete", "create"])
	}
}

test_updating_a_new_type_is_fine if {
	count(deny) == 0 with input as plan("azurerm_managed_disk", ["update"])
}

# Settings around a data store hold no data of their own.
test_replacing_settings_around_a_data_store_is_fine if {
	every type in [
		"azurerm_key_vault_access_policy",
		"azurerm_storage_account_network_rules",
		"azurerm_mssql_firewall_rule",
		"azurerm_redis_firewall_rule",
	] {
		count(deny) == 0 with input as plan(type, ["delete", "create"])
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
