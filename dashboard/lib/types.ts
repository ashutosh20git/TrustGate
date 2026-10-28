// Shapes returned by the TrustGate proxy's analyst API.

export type Metrics = {
  decisions: number
  by_tier_decision: Record<string, number>
  would_block_monitor: number
  fail_closed: number
  latency_ms_p50: number | null
  latency_ms_p95: number | null
  escalations: Record<string, number>
  canary_caught: number
  canary_missed: number
  label_coverage_min: number | null
  alerts: number
  ai_evasion_alerts: number
  audit_chain_ok: boolean
  recheck_analyst_agreement: { resolved: number; agreement_rate: number | null }
  mode: "enforce" | "monitor"
  pack: string
}

export type AlertSummary = {
  alert_id: string
  source: string
  severity: string
  original_severity: string | null
  tags: string[]
  received_at: string
  label_coverage: number
  flagged_evidence: number
  status: AlertStatus
}

/** waiting: an action is held for an analyst; handled: decided, nothing held; new: not triaged yet. */
export type AlertStatus = "waiting" | "handled" | "new"

export type AlertCounts = { all: number } & Record<AlertStatus, number>

export type Evidence = { id: string; field: string; content: string; flags: string[]; origin?: string }

export type Alert = {
  alert_id: string
  source: string
  severity: string
  original_severity: string | null
  tags: string[]
  facts: Record<string, unknown>
  evidence: Evidence[]
  received_at?: string | null
  status?: AlertStatus
}

export type AuditRecord = {
  id: string
  seq: number
  ts: string
  kind: string
  alert_id: string | null
  tool: string | null
  tier: number | null
  decision: string | null
  mode: string | null
  enforced: boolean | null
  reasons: string[]
  recheck_verdict: string | null
  tainted_spans: string[]
  latency_ms: number | null
  details: Record<string, unknown> | null
  record_hash: string
  prev_hash: string
}

export type ProposedAction = {
  alert_id: string
  verdict: string
  tool: string
  args: Record<string, unknown>
  cited_evidence: string[]
  rationale: string
}

export type Escalation = {
  id: string
  created_at: string
  status: "open" | "approved" | "rejected" | "failed" | "expired"
  alert_id: string
  tool: string
  tier: number | null
  action: ProposedAction
  reasons: string[]
  tainted_spans: string[]
  recheck_verdict: string | null
  duplicates: number
  analyst: string | null
  analyst_reason: string | null
  decided_at: string | null
}

export type Explanation = {
  would_allow_if: string[]
  never_automatic: string[]
  notes: string[]
}

export type ActionRecord = {
  id: string
  ts: string
  alert_id: string
  tool: string
  tier: number
  args: Record<string, unknown>
  via: string
  undo_tool: string | null
  undo_args: Record<string, unknown>
  status: "executed" | "reverted" | "revert_failed"
  reverted_at: string | null
  reverted_by: string | null
  revert_reason: string | null
}

export type Rollout = {
  criteria: string
  tools: {
    tool: string
    tier: number
    decisions: number
    would_block: number
    fail_closed: number
    would_block_rate: number
    top_reasons: string[]
    ready_to_enforce: boolean
  }[]
}

export type AnalystScores = { criteria: string; analysts: Record<string, unknown>[] }

export type Pin = {
  server: string
  name: string
  status: "pinned" | "disabled" | "quarantined"
  reasons: string[]
  approved_by: string | null
}

export type Compliance = {
  framework: string
  disclaimer: string
  controls: { id: string; requirement: string; status: "met" | "confirm" | "gap"; evidence: string }[]
}

export type Role = "analyst" | "admin"

export type Me = { name: string; role: Role; source: "setup" | "team" }

export type TeamMember = {
  name: string
  role: Role
  source: "setup" | "team"
  active: boolean
  added_at?: string
  added_by?: string
  token_reset_at?: string | null
  removed_at?: string | null
  removed_by?: string | null
}
