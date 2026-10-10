# Shared floor rules. Every per-app pack includes these; a pack can add rules
# but cannot remove or loosen them (Model Armor "floor settings").
#
# Written defensively: a rule denies unless the input explicitly shows the
# action is safe, so a missing input field can never let an action through.
package trustgate.floor

import rego.v1

deny contains "unknown tool or tier" if not input.tier in {0, 1, 2, 3}

# T1: security-reducing. Both verdicts benign and a typed fact cited.
deny contains "T1: agent verdict is not benign" if {
	input.tier == 1
	not input.agent_verdict == "benign"
}

deny contains "T1: facts-only re-check is not benign" if {
	input.tier == 1
	not input.recheck_verdict == "benign"
}

deny contains "T1: no typed-fact citation" if {
	input.tier == 1
	not cites_typed_fact
}

# Untrusted text can raise suspicion but never lower it.
deny contains "T1: AI-evasion attempt on this alert" if {
	input.tier == 1
	not input.ai_evasion_attempt == false
}

# T2: disruptive. The target must be an exact typed-fact value.
deny contains "T2: target not in typed facts" if {
	input.tier == 2
	not input.target in input.fact_targets
}

# T3: outbound. No raw evidence and no floor-blocked entities may leave.
deny contains "T3: raw evidence in outbound payload" if {
	input.tier == 3
	not input.contains_raw_evidence == false
}

deny contains sprintf("T3: %s may never leave", [entity]) if {
	input.tier == 3
	some entity in input.output_entities
	entity in data.floor.block_entities
}

# v2: MCP tools must still match the description pinned at registration.
deny contains "MCP tool not pinned or changed since pinning" if {
	input.mcp.server
	not input.mcp.pinned_ok == true
}

cites_typed_fact if {
	some c in input.cited
	startswith(c, "facts.")
}
