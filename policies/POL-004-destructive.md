---
id: POL-004
type: policy
status: accepted
applies_to:
  - azurerm_mssql_database
  - azurerm_mssql_server
  - azurerm_postgresql_flexible_server
  - azurerm_mysql_flexible_server
  - azurerm_cosmosdb_account
  - azurerm_storage_account
  - azurerm_key_vault
topics: [security]
severity: high
rego: POL-004-destructive.rego
---

# POL-004: Replacing or deleting something that holds data

## Requirement

A plan must not delete or replace a resource that holds data without someone deciding that's intended. A replacement destroys the old resource first, or shortly after the new one exists, and what it held goes with it unless it was backed up or moved.

A change that forces a replacement often doesn't look like one in the code: renaming a database or changing an immutable setting is enough. Confirm the data is backed up or disposable, or change the plan so that it updates in place.

## Enforcement

`POL-004-destructive.rego` reports every planned `delete` on the resource types in `applies_to`, including the delete half of a replacement. Add a type there and to the policy together. It reports the plan, not a mistake: a repo that really means to do this merges anyway.
