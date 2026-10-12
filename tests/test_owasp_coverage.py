"""OWASP coverage matrix (docs/BENCHMARKS.md): every claim points at the test that proves it.

OWASP Top 10 for LLM Applications 2025, and OWASP Agentic AI Threats and Mitigations (T1-T15).
The test below fails if a referenced test is renamed or deleted, so the matrix cannot drift from
the code. "n/a" items name why they do not apply; "partial" items name what is not covered.
"""

from __future__ import annotations

import ast
from pathlib import Path

TESTS = Path(__file__).parent

# id: (title, status, tests proving it, note)
MATRIX: dict[str, tuple[str, str, list[str], str]] = {
    "LLM01": ("Prompt injection", "covered",
              ["test_close_benign_on_malicious_facts_escalates", "test_ai_evasion_tag_blocks_t1",
               "test_detector_sees_the_important_instructions_attack", "test_rot13_injection_detected_at_ingest"],
              "Adaptive red-team, AgentDojo, InjecAgent, ASB in docs/BENCHMARKS.md"),
    "LLM02": ("Sensitive information disclosure", "covered",
              ["test_t3_plain_secret_still_blocked_and_clean_body_allowed", "test_every_transform_the_red_team_used_is_caught",
               "test_a_secret_split_across_messages_escalates_at_the_part_that_completes_it", "test_t3_raw_evidence_in_body_escalates"], ""),
    "LLM03": ("Supply chain", "covered",
              ["test_rug_pull_disables_tool", "test_poisoned_description_quarantined", "test_shadowing_quarantined",
               "test_repin_requires_approval_and_is_audited"], "MCP tool pinning; dependencies: pip-audit, Trivy in CI"),
    "LLM04": ("Data and model poisoning", "partial",
              ["test_model_trained_on_another_fact_list_is_refused", "test_training_rejects_bad_labels",
               "test_recheck_prompt_excludes_all_evidence_text", "test_ensemble_needs_both_judges_for_benign"],
              "The re-check never sees attacker text; a poisoned training file is caught only by its holdout rate"),
    "LLM05": ("Improper output handling", "covered",
              ["test_tool_result_wrapped_and_injection_tags_alert", "test_delimiter_in_content_cannot_close_wrapper",
               "test_t3_from_tainted_alert_carries_stamp"], ""),
    "LLM06": ("Excessive agency", "covered",
              ["test_t2_target_not_in_facts_escalates", "test_blocking_an_ip_needs_its_own_threat_evidence",
               "test_second_security_reducing_action_on_an_alert_escalates", "test_unknown_tool_raises_then_escalates",
               "test_reverse_actions_are_not_agent_tools"], ""),
    "LLM07": ("System prompt leakage", "covered",
              ["test_tool_response_hides_reasons_and_views_need_token", "test_judges_reasons_reach_the_analyst_not_the_agent"],
              "Nothing secret is in a prompt; the gate's reasons never reach the agent"),
    "LLM08": ("Vector and embedding weaknesses", "n/a", [], "No retrieval or vector store"),
    "LLM09": ("Misinformation", "partial",
              ["test_close_benign_on_benign_facts_needs_typed_fact_citation", "test_t1_citing_unrelated_fact_escalates"],
              "A wrong verdict cannot act without facts; a wrong summary in a T0 note is not checked"),
    "LLM10": ("Unbounded consumption", "covered",
              ["test_saturated_gate_fails_closed_immediately", "test_t3_oversize_payload_escalates",
               "test_t1_campaign_limit_per_sender_domain", "test_timeout_escalates"], "Plus fuzzing: no input over 3.4 s"),
    "AT-T1": ("Memory poisoning", "partial", ["test_note_after_flagged_evidence_carries_provenance"],
              "The agent keeps no memory between alerts; notes carry provenance"),
    "AT-T2": ("Tool misuse", "covered", ["test_t2_target_not_in_facts_escalates", "test_t3_to_attacker_escalates",
                                          "test_undo_tools_hidden_and_refused"], ""),
    "AT-T3": ("Privilege compromise", "covered", ["test_t2_approval_needs_two_distinct_tokens",
                                                   "test_approval_needs_an_analyst_identity", "test_tier_drift_refuses_approval"], ""),
    "AT-T4": ("Resource overload", "covered", ["test_saturated_gate_fails_closed_immediately", "test_proxy_api_fuzz_authenticated"], ""),
    "AT-T5": ("Cascading hallucination", "covered", ["test_receiving_gate_keeps_upstream_suspicion",
                                                      "test_close_benign_on_malicious_facts_escalates"], ""),
    "AT-T6": ("Intent breaking and goal manipulation", "covered",
              ["test_close_benign_on_malicious_facts_escalates", "test_full_t1_judgement_lets_no_affordable_attack_through"], ""),
    "AT-T7": ("Misaligned and deceptive behaviour", "covered",
              ["test_t1_citing_unrelated_fact_escalates", "test_floor_denies_t1_without_cited_support"],
              "The gate checks facts, not the agent's stated reasons"),
    "AT-T8": ("Repudiation and untraceability", "covered",
              ["test_edit_is_caught", "test_rewriting_the_whole_chain_needs_the_export", "test_concurrent_writers_keep_one_chain"], ""),
    "AT-T9": ("Identity spoofing", "covered", ["test_forged_alert_without_valid_token_is_refused",
                                                "test_attacker_authserv_header_is_spoofed_not_a_fact", "test_directory_identifies_by_token_only"], ""),
    "AT-T10": ("Overwhelming the human in the loop", "partial",
               ["test_analyst_scores_flag_rubber_stamping", "test_real_escalation_never_merges_into_a_canary"],
               "Canaries and scores show rubber-stamping; queue volume itself is not capped"),
    "AT-T11": ("Unexpected code execution", "n/a", [], "No code-execution tool is exposed; an unregistered tool escalates"),
    "AT-T12": ("Agent communication poisoning", "covered", ["test_receiving_gate_keeps_upstream_suspicion",
                                                             "test_stamp_round_trip_and_forgery"], ""),
    "AT-T13": ("Rogue agents", "covered", ["test_call_blocked_when_tool_changed", "test_poisoned_tool_hidden_from_list"], ""),
    "AT-T14": ("Human attacks on multi-agent systems", "covered", ["test_t2_approval_needs_two_analysts",
                                                                   "test_approval_refuses_encoded_floor_blocked_secret"], ""),
    "AT-T15": ("Human manipulation", "covered", ["test_tool_response_hides_reasons_and_views_need_token",
                                                  "test_t3_restated_evidence_escalates"], ""),
}


def _all_test_names() -> set[str]:
    names = set()
    for path in TESTS.glob("test_*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                names.add(node.name)
    return names


def test_every_matrix_claim_names_a_test_that_exists():
    names = _all_test_names()
    for item, (title, status, tests, note) in MATRIX.items():
        assert status in {"covered", "partial", "n/a"}, item
        if status == "n/a":
            assert note and not tests, item
            continue
        assert tests, f"{item} {title} claims coverage without a test"
        missing = [t for t in tests if t not in names]
        assert not missing, f"{item} {title}: tests not found: {missing}"
        if status == "partial":
            assert note, f"{item} is partial but does not say what is missing"


def test_matrix_lists_all_owasp_items():
    assert {f"LLM{i:02d}" for i in range(1, 11)} <= set(MATRIX)
    assert {f"AT-T{i}" for i in range(1, 16)} <= set(MATRIX)
