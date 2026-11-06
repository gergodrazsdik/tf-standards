package pol004

import rego.v1

data_holding := {
	"azurerm_mssql_server",
	"azurerm_mssql_database",
	"azurerm_mssql_managed_instance",
	"azurerm_mssql_managed_database",
	"azurerm_postgresql_flexible_server",
	"azurerm_postgresql_flexible_server_database",
	"azurerm_mysql_flexible_server",
	"azurerm_mysql_flexible_database",
	"azurerm_cosmosdb_account",
	"azurerm_cosmosdb_sql_database",
	"azurerm_cosmosdb_sql_container",
	"azurerm_redis_cache",
	"azurerm_storage_account",
	"azurerm_storage_container",
	"azurerm_storage_share",
	"azurerm_managed_disk",
	"azurerm_key_vault",
	"azurerm_key_vault_key",
	"azurerm_key_vault_secret",
}

deny contains result if {
	some rc in input.resource_changes
	rc.type in data_holding
	rc.mode == "managed"
	"delete" in rc.change.actions
	result := {
		"msg": sprintf("POL-004: %s: this plan %s a resource that holds data", [rc.address, verb(rc.change.actions)]),
		"details": {"doc_id": "POL-004", "address": rc.address, "severity": "high"},
	}
}

verb(actions) := "replaces" if "create" in actions

verb(actions) := "deletes" if not "create" in actions
