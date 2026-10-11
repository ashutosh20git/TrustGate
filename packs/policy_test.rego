# Unit tests for the policy floor and the SOC pack: `opa test packs/ -v` (run in CI).
# They pin what each rule allows and denies, so a policy change that loosens the
# floor fails CI before the attack suite even runs.
package trustgate.policy_test

import rego.v1

t1_ok := {
	"pack": "soc", "tool": "close_alert", "tier": 1, "agent_verdict": "benign", "recheck_verdict": "benign",
	"cited": ["facts.dmarc_pass"], "alert_severity": "low", "ai_evasion_attempt": false,
	"contains_raw_evidence": false, "output_entities": [],
	"t1_evidence": {
		"unknown_core": [], "costly_support": ["sender_prior_messages >= 3"], "costly_ok": true,
		"enrichment_failed": false, "cited_support": ["dmarc_pass"], "cited_support_ok": true,
	},
	"scope": {"required": false, "ok": true},
	"history": {"t1_executed": 0, "t2_executed": 0, "tools": []},
}

test_t1_allowed_when_every_check_holds if {
	data.trustgate.soc.decision.allow with input as t1_ok
}

test_t1_denied_without_evidence_floor if {
	not data.trustgate.soc.decision.allow with input as object.remove(t1_ok, ["t1_evidence"])
}

test_t1_denied_without_history if {
	not data.trustgate.soc.decision.allow with input as object.remove(t1_ok, ["history"])
}

test_t1_denied_after_another_t1 if {
	d := data.trustgate.soc.decision with input as object.union(t1_ok, {"history": {"t1_executed": 1}})
	not d.allow
	"T1: a security-reducing action already ran on this alert; another needs a human" in d.deny
}

test_t1_denied_on_ai_evasion if {
	not data.trustgate.soc.decision.allow with input as object.union(t1_ok, {"ai_evasion_attempt": true})
}

test_t1_denied_on_critical_alert if {
	not data.trustgate.soc.decision.allow with input as object.union(t1_ok, {"alert_severity": "critical"})
}

test_t1_denied_when_recheck_disagrees if {
	not data.trustgate.soc.decision.allow with input as object.union(t1_ok, {"recheck_verdict": "malicious"})
}

test_t1_denied_without_bounded_expiry if {
	not data.trustgate.soc.decision.allow with input as object.union(t1_ok, {"scope": {"required": true, "ok": false}})
}

t2 := {
	"pack": "soc", "tool": "block_ip", "tier": 2, "agent_verdict": "malicious", "cited": ["facts.ioc_ips"],
	"alert_severity": "high", "ai_evasion_attempt": false, "contains_raw_evidence": false, "output_entities": [],
	"target": "203.0.113.9", "fact_targets": ["203.0.113.9"],
}

test_t2_allowed_on_typed_fact_target if {
	data.trustgate.soc.decision.allow with input as t2
}

test_t2_denied_off_facts if {
	not data.trustgate.soc.decision.allow with input as object.union(t2, {"target": "198.51.100.7"})
}

test_t2_denied_on_critical_asset if {
	not data.trustgate.soc.decision.allow with input as object.union(t2, {"target": "10.0.0.10", "fact_targets": ["10.0.0.10"]})
}

t3 := {
	"pack": "soc", "tool": "send_email", "tier": 3, "agent_verdict": "malicious", "cited": [],
	"alert_severity": "high", "ai_evasion_attempt": false, "contains_raw_evidence": false, "output_entities": [],
	"recipient": "soc-team@corp.example",
}

test_t3_allowed_to_allowlisted_recipient if {
	data.trustgate.soc.decision.allow with input as t3
}

test_t3_denied_to_other_recipient if {
	not data.trustgate.soc.decision.allow with input as object.union(t3, {"recipient": "drop@exfil.example"})
}

test_t3_denied_with_raw_evidence if {
	not data.trustgate.soc.decision.allow with input as object.union(t3, {"contains_raw_evidence": true})
}

test_t3_denied_with_floor_blocked_entity if {
	not data.trustgate.soc.decision.allow with input as object.union(t3, {"output_entities": ["CREDIT_CARD"]})
}

test_unknown_tool_denied if {
	not data.trustgate.soc.decision.allow with input as object.union(t1_ok, {"tool": "rm_rf"})
}
