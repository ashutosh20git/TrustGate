# Generic policy pack: any tool-using agent (the demo's email assistant).
# Pack data lives in generic.json (data.packs.generic); shared rules in floor.rego.
package trustgate.generic

import rego.v1

pack := data.packs.generic

deny contains msg if some msg in data.trustgate.floor.deny

deny contains "tool is not in the generic pack" if not pack.tools[input.tool]

deny contains "tool tier differs from the generic pack's tier map" if {
	pack.tools[input.tool] != input.tier
}

deny contains "T2: target is protected; a human must approve" if {
	input.tier == 2
	input.target in pack.critical_assets
}

deny contains "T3: recipient not on the allowlist" if {
	input.tier == 3
	not input.recipient in pack.allowlist
}

deny contains sprintf("T3: generic pack blocks %s in outbound payloads", [entity]) if {
	input.tier == 3
	some entity in input.output_entities
	entity in pack.output_scan.block_entities
}

default allow := false

allow if count(deny) == 0

decision := {"allow": allow, "deny": deny}
