# SOC policy pack: the AI SOC triage agent from the demo.
# Pack data lives in soc.json (data.packs.soc); shared rules in floor.rego.
package trustgate.soc

import rego.v1

pack := data.packs.soc

deny contains msg if some msg in data.trustgate.floor.deny

deny contains "tool is not in the SOC pack" if not pack.tools[input.tool]

deny contains "tool tier differs from the SOC pack's tier map" if {
	pack.tools[input.tool] != input.tier
}

# SOC-specific: closing or downgrading a critical alert always needs a human.
deny contains "T1 on a critical alert needs a human" if {
	input.tier == 1
	input.alert_severity == "critical"
}

deny contains "T2: target is a critical asset; a human must approve" if {
	input.tier == 2
	input.target in pack.critical_assets
}

deny contains "T3: recipient not on the SOC allowlist" if {
	input.tier == 3
	not input.recipient in pack.allowlist
}

deny contains sprintf("T3: SOC pack blocks %s in outbound payloads", [entity]) if {
	input.tier == 3
	some entity in input.output_entities
	entity in pack.output_scan.block_entities
}

default allow := false

allow if count(deny) == 0

decision := {"allow": allow, "deny": deny}
