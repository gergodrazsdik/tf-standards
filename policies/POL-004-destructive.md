---
id: POL-004
type: policy
status: accepted
applies_to:
  - azurerm_mssql_server
  - azurerm_mssql_database
  - azurerm_mssql_managed_instance
  - azurerm_mssql_managed_database
  - azurerm_postgresql_flexible_server
  - azurerm_postgresql_flexible_server_database
  - azurerm_mysql_flexible_server
  - azurerm_mysql_flexible_database
  - azurerm_cosmosdb_account
  - azurerm_cosmosdb_sql_database
  - azurerm_cosmosdb_sql_container
  - azurerm_redis_cache
  - azurerm_storage_account
  - azurerm_storage_container
  - azurerm_storage_share
  - azurerm_managed_disk
  - azurerm_key_vault
  - azurerm_key_vault_key
  - azurerm_key_vault_secret
topics: [security]
severity: high
rego: POL-004-destructive.rego
---

# POL-004: Replacing or deleting something that holds data

## Requirement

A plan must not delete or replace a resource that holds data without someone deciding that's intended. A replacement destroys the old resource first, or shortly after the new one exists, and what it held goes with it unless it was backed up or moved.

A change that forces a replacement often doesn't look like one in the code: renaming a database or changing an immutable setting is enough. Confirm the data is backed up or disposable, or change the plan so that it updates in place.

## Enforcement

`POL-004-destructive.rego` reports every planned `delete` on the resource types in `applies_to`, including the delete half of a replacement. The list keeps to types whose deletion loses the data itself: database servers and their databases, Cosmos DB accounts, databases and containers, Redis caches, storage accounts with their containers and shares, managed disks, and key vaults with their keys and secrets, where a deleted key can leave data encrypted with it unreadable. Settings around them, such as firewall rules or access policies, hold no data and aren't listed. Add a type there and to the policy together. It reports the plan, not a mistake: a repo that really means to do this merges anyway.
