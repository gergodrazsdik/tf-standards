package pol001

import rego.v1

required := {
	"allow_nested_items_to_be_public": false,
	"https_traffic_only_enabled": true,
	"min_tls_version": "TLS1_2",
}

deny contains result if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_account"
	rc.mode == "managed"
	some action in rc.change.actions
	action in {"create", "update"}
	some attribute, value in required
	not compliant(rc.change.after, attribute, value)
	result := {
		"msg": sprintf("POL-001: %s: %s must be %v", [rc.address, attribute, value]),
		"details": {"doc_id": "POL-001", "address": rc.address, "severity": "high"},
	}
}

# Compares with object.get, so that a required false value still counts as set.
compliant(after, attribute, value) if object.get(after, attribute, null) == value
