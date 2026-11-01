package adr001

import rego.v1

patterns := {
	"azurerm_resource_group": `^rg-[a-z0-9]+(-[a-z0-9]+)*-(dev|test|prod)$`,
	"azurerm_virtual_network": `^vnet-[a-z0-9]+(-[a-z0-9]+)*-(dev|test|prod)$`,
	"azurerm_user_assigned_identity": `^id-[a-z0-9]+(-[a-z0-9]+)*-(dev|test|prod)$`,
	"azurerm_storage_account": `^st[a-z0-9]+(dev|test|prod)$`,
}

deny contains result if {
	some rc in input.resource_changes
	rc.mode == "managed"
	some action in rc.change.actions
	action in {"create", "update"}
	pattern := patterns[rc.type]
	name := rc.change.after.name
	not regex.match(pattern, name)
	result := {
		"msg": sprintf("ADR-001: %s: name %q does not match %s", [rc.address, name, pattern]),
		"details": {"doc_id": "ADR-001", "address": rc.address, "severity": "low"},
	}
}
