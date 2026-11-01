package pol002

import rego.v1

internet_sources := {"*", "0.0.0.0/0", "::/0", "internet", "any"}

admin_ports := {22, 3389}

deny contains result if {
	some rc in input.resource_changes
	rc.type == "azurerm_network_security_rule"
	judged(rc)
	open_admin_port(rc.change.after)
	result := finding(rc, "source_address_prefix")
}

deny contains result if {
	some rc in input.resource_changes
	rc.type == "azurerm_network_security_group"
	judged(rc)
	some rule in rc.change.after.security_rule
	open_admin_port(rule)
	result := finding(rc, "security_rule")
}

judged(rc) if {
	rc.mode == "managed"
	some action in rc.change.actions
	action in {"create", "update"}
}

finding(rc, attribute) := {
	"msg": sprintf("POL-002: %s: an inbound rule allows an admin port from the internet", [rc.address]),
	"details": {"doc_id": "POL-002", "address": rc.address, "severity": "high", "attribute": attribute},
}

open_admin_port(rule) if {
	lower(rule.direction) == "inbound"
	lower(rule.access) == "allow"
	from_internet(rule)
	some port in admin_ports
	covers_port(rule, port)
}

from_internet(rule) if lower(rule.source_address_prefix) in internet_sources

from_internet(rule) if {
	some prefix in rule.source_address_prefixes
	lower(prefix) in internet_sources
}

covers_port(rule, port) if port_spec_covers(rule.destination_port_range, port)

covers_port(rule, port) if {
	some spec in rule.destination_port_ranges
	port_spec_covers(spec, port)
}

port_spec_covers("*", _)

port_spec_covers(spec, port) if to_number(spec) == port

port_spec_covers(spec, port) if {
	contains(spec, "-")
	bounds := split(spec, "-")
	to_number(bounds[0]) <= port
	port <= to_number(bounds[1])
}
