package pol003

import rego.v1

plan(after) := {"resource_changes": [{
	"address": "azurerm_role_assignment.x",
	"type": "azurerm_role_assignment",
	"mode": "managed",
	"change": {"actions": ["create"], "after": after},
}]}

owner_at(scope) := {"role_definition_name": "Owner", "scope": scope}

# C3, with the subscription ID as the reviewer's placeholder and as a real ID.
test_owner_at_subscription if {
	every scope in ["/subscriptions/[redacted:1]", "/subscriptions/00000000-0000-0000-0000-000000000000"] {
		count(deny) == 1 with input as plan(owner_at(scope))
	}
}

test_reports_the_attribute if {
	some result in deny with input as plan(owner_at("/subscriptions/x"))
	result.details.attribute == "role_definition_name"
	result.details.doc_id == "POL-003"
	result.details.severity == "high"
}

test_user_access_administrator if {
	count(deny) == 1 with input as plan({"role_definition_name": "User Access Administrator", "scope": "/subscriptions/x"})
}

test_role_in_any_case if {
	count(deny) == 1 with input as plan({"role_definition_name": "OWNER", "scope": "/subscriptions/x"})
}

test_management_group if {
	count(deny) == 1 with input as plan(owner_at("/providers/Microsoft.Management/managementGroups/root"))
}

test_root if {
	count(deny) == 1 with input as plan(owner_at("/"))
}

test_resource_group_is_fine if {
	count(deny) == 0 with input as plan(owner_at("/subscriptions/x/resourceGroups/rg"))
}

test_narrower_role_is_fine if {
	count(deny) == 0 with input as plan({"role_definition_name": "Reader", "scope": "/subscriptions/x"})
}

test_contributor_isnt_this_policy if {
	count(deny) == 0 with input as plan({"role_definition_name": "Contributor", "scope": "/subscriptions/x"})
}

test_role_named_by_id_cant_be_judged if {
	count(deny) == 0 with input as plan({"role_definition_id": "[redacted:1]", "scope": "/subscriptions/x"})
}
