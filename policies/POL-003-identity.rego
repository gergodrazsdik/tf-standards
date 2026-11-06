package pol003

import rego.v1

broad_roles := {"owner", "user access administrator"}

# The built-in roles' definition IDs are the same in every tenant, so the reviewer's redactor keeps them.
broad_role_ids := {
	"8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
	"18d7d88d-d35e-4fb5-a5c3-7773c4a72b09": "User Access Administrator",
}

deny contains result if {
	some rc in input.resource_changes
	rc.type == "azurerm_role_assignment"
	rc.mode == "managed"
	some action in rc.change.actions
	action in {"create", "update"}
	role := broad_role(rc.change.after)
	wide_scope(rc.change.after.scope)
	result := {
		"msg": sprintf("POL-003: %s: %s granted at subscription scope or wider", [rc.address, role.name]),
		"details": {"doc_id": "POL-003", "address": rc.address, "severity": "high", "attribute": role.attribute},
	}
}

# The name wins when the plan has both, so an assignment gives one finding.
broad_role(after) := {"name": after.role_definition_name, "attribute": "role_definition_name"} if {
	lower(after.role_definition_name) in broad_roles
} else := {"name": broad_role_ids[id], "attribute": "role_definition_id"} if {
	id := role_definition_guid(after.role_definition_id)
}

# Any scope prefix: a subscription's, a management group's, or none.
role_definition_guid(id) := lower(match[0][1]) if {
	match := regex.find_all_string_submatch_n(
		`(?i)^(?:/.*)?/providers/Microsoft\.Authorization/roleDefinitions/([0-9a-f-]{36})/?$`,
		id, 1,
	)
	count(match) == 1
}

# The subscription's ID can be a placeholder, because the reviewer removes GUIDs from plans.
wide_scope(scope) if regex.match(`(?i)^/subscriptions/[^/]+/?$`, scope)

wide_scope(scope) if regex.match(`(?i)^/providers/Microsoft\.Management/managementGroups/`, scope)

wide_scope(scope) if scope == "/"
