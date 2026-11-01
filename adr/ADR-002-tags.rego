package adr002

import rego.v1

required := {"owner", "environment", "project"}

# Only attributes present in the planned values count: resources without tags support have no "tags" key.
taggable(rc) if "tags" in object.keys(rc.change.after)

present(rc, tag) if {
	value := rc.change.after.tags[tag]
	value != ""
}

# A value known only after apply can't be judged at plan time.
present(rc, tag) if rc.change.after_unknown.tags[tag] == true

present(rc, _) if rc.change.after_unknown.tags == true

deny contains result if {
	some rc in input.resource_changes
	rc.mode == "managed"
	some action in rc.change.actions
	action in {"create", "update"}
	taggable(rc)
	some tag in required
	not present(rc, tag)
	result := {
		"msg": sprintf("ADR-002: %s: required tag %q is missing or empty", [rc.address, tag]),
		"details": {"doc_id": "ADR-002", "address": rc.address, "severity": "medium"},
	}
}
