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

owner_id := "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"

owner_by_id(id, scope) := {"role_definition_id": id, "scope": scope}

test_owner_by_id_at_any_prefix if {
	every id in [
		sprintf("/subscriptions/[redacted:1]/providers/Microsoft.Authorization/roleDefinitions/%s", [owner_id]),
		sprintf("/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/roleDefinitions/%s", [owner_id]),
		sprintf("/providers/Microsoft.Authorization/roleDefinitions/%s", [owner_id]),
		sprintf("/providers/microsoft.authorization/roledefinitions/%s", [upper(owner_id)]),
		sprintf("/providers/Microsoft.Management/managementGroups/root/providers/Microsoft.Authorization/roleDefinitions/%s", [owner_id]),
	] {
		count(deny) == 1 with input as plan(owner_by_id(id, "/subscriptions/x"))
	}
}

test_owner_by_id_reports_the_id if {
	id := sprintf("/providers/Microsoft.Authorization/roleDefinitions/%s", [owner_id])
	some result in deny with input as plan(owner_by_id(id, "/subscriptions/x"))
	result.details.attribute == "role_definition_id"
	contains(result.msg, "Owner granted")
}

test_user_access_administrator_by_id if {
	id := "/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c4a72b09"
	count(deny) == 1 with input as plan(owner_by_id(id, "/subscriptions/x"))
}

test_name_and_id_give_one_finding if {
	after := {
		"role_definition_name": "Owner",
		"role_definition_id": sprintf("/providers/Microsoft.Authorization/roleDefinitions/%s", [owner_id]),
		"scope": "/subscriptions/x",
	}
	some result in deny with input as plan(after)
	result.details.attribute == "role_definition_name"
	count(deny) == 1 with input as plan(after)
}

test_owner_by_id_at_resource_group_is_fine if {
	id := sprintf("/providers/Microsoft.Authorization/roleDefinitions/%s", [owner_id])
	count(deny) == 0 with input as plan(owner_by_id(id, "/subscriptions/x/resourceGroups/rg"))
}

# Reader's ID.
test_narrower_role_by_id_is_fine if {
	id := "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"
	count(deny) == 0 with input as plan(owner_by_id(id, "/subscriptions/x"))
}

test_owner_id_inside_a_longer_path_is_fine if {
	id := sprintf("/providers/Microsoft.Authorization/roleDefinitions/%s/extra", [owner_id])
	count(deny) == 0 with input as plan(owner_by_id(id, "/subscriptions/x"))
}

# A custom role's ID is tenant data, so the redactor still replaces it.
test_redacted_role_id_cant_be_judged if {
	count(deny) == 0 with input as plan(owner_by_id("/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/[redacted:1]", "/subscriptions/x"))
}
