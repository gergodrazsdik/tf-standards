package pol003

import rego.v1

broad_roles := {"owner", "user access administrator"}

deny contains result if {
	some rc in input.resource_changes
	rc.type == "azurerm_role_assignment"
	rc.mode == "managed"
	some action in rc.change.actions
	action in {"create", "update"}
	lower(rc.change.after.role_definition_name) in broad_roles
	wide_scope(rc.change.after.scope)
	result := {
		"msg": sprintf("POL-003: %s: %s granted at subscription scope or wider", [rc.address, rc.change.after.role_definition_name]),
		"details": {"doc_id": "POL-003", "address": rc.address, "severity": "high", "attribute": "role_definition_name"},
	}
}

# The subscription's ID can be a placeholder, because the reviewer removes GUIDs from plans.
wide_scope(scope) if regex.match(`(?i)^/subscriptions/[^/]+/?$`, scope)

wide_scope(scope) if regex.match(`(?i)^/providers/Microsoft\.Management/managementGroups/`, scope)

wide_scope(scope) if scope == "/"
