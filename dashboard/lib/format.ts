import type { AlertStatus, AuditRecord } from "./types"

// Everything here turns the gate's records into plain words. The exact originals stay
// available in each detail view.

export type Tone = "success" | "warning" | "danger" | "info" | "violet" | "neutral"

const TOOL_LABELS: Record<string, string> = {
  get_alert: "Read the alert",
  query_logs: "Read logs",
  lookup_ioc: "Look up an indicator",
  enrich: "Read enrichment",
  add_note: "Add a note",
  escalate: "Escalate to an analyst",
  raise_severity: "Raise severity",
  close_alert: "Close the alert",
  downgrade_severity: "Lower severity",
  whitelist_indicator: "Allowlist an indicator",
  suppress_rule: "Suppress a detection rule",
  block_ip: "Block an IP",
  isolate_host: "Isolate a host",
  disable_account: "Disable an account",
  send_email: "Send an email",
  post_webhook: "Post a webhook",
}

export const TIERS: Record<number, { label: string; tone: Tone; hint: string }> = {
  0: { label: "Read-only", tone: "neutral", hint: "Reads or annotates; always allowed" },
  1: { label: "Lowers security", tone: "warning", hint: "Closes, downgrades, allowlists or suppresses" },
  2: { label: "Disruptive", tone: "danger", hint: "Blocks, isolates or disables" },
  3: { label: "Sends data out", tone: "violet", hint: "Emails or webhooks" },
}

export const FLAG_LABELS: Record<string, string> = {
  hidden_text: "Hidden text",
  injection: "Aimed at the AI",
  macros: "Macros",
  unparseable: "Could not be read",
  truncated: "Truncated",
  embedded_file: "Embedded file",
  type_mismatch: "File type mismatch",
  pdf_active_content: "Active PDF content",
}

export function toolLabel(tool: string | null | undefined): string {
  if (!tool) return "—"
  const slash = tool.lastIndexOf("/")
  const name = slash >= 0 ? tool.slice(slash + 1) : tool
  const label = TOOL_LABELS[name] ?? sentence(name.replaceAll("_", " "))
  return slash >= 0 ? `${label} (via ${tool.slice(0, slash)})` : label
}

export function sentence(text: string): string {
  return text ? text[0].toUpperCase() + text.slice(1) : text
}

export function tierOf(tier: number | null | undefined) {
  return tier == null ? { label: "—", tone: "neutral" as Tone, hint: "" } : (TIERS[tier] ?? TIERS[0])
}

export function plainReason(reason: string): string {
  const disagree = /^facts and text disagree: agent=(\w+), facts-only=(\w+)/.exec(reason)
  if (disagree) return `The AI said “${disagree[1]}”, but the trusted facts alone say “${disagree[2]}”.`
  const fixed: Record<string, string> = {
    "T1: AI-evasion attempt on this alert": "The alert contains text aimed at manipulating the AI.",
    "T1: no fact the attacker cannot cheaply control supports benign": "Nothing an attacker can't fake supports “benign”.",
    "T1: no cited typed fact supports benign": "The AI didn't cite a trusted fact that supports “benign”.",
    "unknown tool": "The AI asked for a tool TrustGate doesn't know.",
    "schema: unknown alert": "The action names an alert TrustGate never received.",
    "target not in typed facts": "The target isn't in the alert's trusted facts.",
    "monitor mode: would block": "Monitor mode: this would have been held, but it ran anyway.",
    "MCP tool not pinned or changed since pinning": "The MCP tool isn't approved, or changed since it was.",
  }
  if (fixed[reason]) return fixed[reason]
  const prefixes: [string, string][] = [
    ["re-check: scorecard: ", "Fact check: "],
    ["re-check: ", "Fact check: "],
    ["schema: invalid arguments for ", "Incomplete request: "],
    ["schema: ", "Invalid request: "],
    ["fail-closed: ", "A check failed or timed out, so it was held to be safe: "],
    ["T1: ", ""],
    ["T2: ", ""],
    ["T3: ", ""],
  ]
  for (const [prefix, lead] of prefixes) {
    if (reason.startsWith(prefix)) return lead + sentence(reason.slice(prefix.length))
  }
  return sentence(reason)
}

export function describe(rec: AuditRecord): { text: string; tone: Tone } {
  const tool = toolLabel(rec.tool)
  const d = (rec.details ?? {}) as Record<string, string | boolean | undefined>
  const verdict = typeof d.verdict === "string" && d.verdict !== "unsure" ? ` — the AI said “${d.verdict}”` : ""
  switch (rec.kind) {
    case "decision":
      if (rec.decision === "allow") return { text: `TrustGate allowed “${tool}”${verdict}`, tone: "success" }
      if (rec.decision === "block") return { text: `TrustGate blocked “${tool}”${verdict}`, tone: "danger" }
      if (rec.enforced === false) return { text: `Monitor mode: TrustGate would have held “${tool}”${verdict}`, tone: "warning" }
      return { text: `TrustGate held “${tool}” for an analyst${verdict}`, tone: "warning" }
    case "execution":
      return { text: `“${tool}” was carried out${d.monitor ? " (monitor mode)" : ""}`, tone: "info" }
    case "execution_failed":
      return { text: `“${tool}” failed to run (${d.error ?? "error"})`, tone: "danger" }
    case "analyst": {
      if (d.canary) {
        return d.canary === "canary_caught"
          ? { text: "A practice case was correctly rejected", tone: "success" }
          : { text: "A practice case was approved by mistake", tone: "danger" }
      }
      if (d.refused) return { text: `Approval of “${tool}” was refused: ${d.refused}`, tone: "danger" }
      const who = (d.analyst as string) || "An analyst"
      const second = d.second_analyst ? ` and ${d.second_analyst}` : ""
      return d.approved
        ? { text: `${who}${second} approved “${tool}”`, tone: "success" }
        : { text: `${who} rejected “${tool}”`, tone: "neutral" }
    }
    case "revert":
      return d.status === "reverted"
        ? { text: `“${tool}” was undone by ${d.by ?? "an analyst"}`, tone: "violet" }
        : { text: `Undoing “${tool}” didn't work (${d.status})`, tone: "danger" }
    case "mcp_pin":
      return { text: `MCP tool ${rec.tool}: ${d.event ?? "updated"}`, tone: "neutral" }
    case "mcp_output":
      return { text: `An injection attempt was found in a result from ${rec.tool}`, tone: "danger" }
    case "team": {
      const by = d.by ?? "An admin"
      if (d.event === "added") return { text: `${by} added ${d.member} as ${d.role === "admin" ? "an admin" : "an analyst"}`, tone: "info" }
      if (d.event === "removed") return { text: `${by} removed ${d.member} from the team`, tone: "neutral" }
      return { text: `${by} reset ${d.member}'s token`, tone: "neutral" }
    }
    default:
      return { text: `${rec.kind}: ${tool}`, tone: "neutral" }
  }
}

export const ALERT_STATUS: Record<AlertStatus, { label: string; tone: Tone }> = {
  waiting: { label: "Waiting for review", tone: "warning" },
  handled: { label: "Handled", tone: "success" },
  new: { label: "Not triaged yet", tone: "neutral" },
}

export const EVENT_KINDS: Record<string, string> = {
  decision: "Decisions",
  execution: "Actions carried out",
  execution_failed: "Failures",
  analyst: "Analyst decisions",
  revert: "Undo",
  mcp_pin: "MCP tool changes",
  mcp_output: "MCP injection alerts",
  team: "Team changes",
}

function parse(ts: string | null | undefined): Date | null {
  if (!ts) return null
  const date = new Date(/[zZ]|[+-]\d\d:\d\d$/.test(ts) ? ts : `${ts}Z`)
  return Number.isNaN(date.getTime()) ? null : date
}

export function ago(ts: string | null | undefined): string {
  const date = parse(ts)
  if (!date) return ""
  const secs = Math.round((Date.now() - date.getTime()) / 1000)
  if (secs < 60) return "just now"
  for (const [size, unit] of [[86400, "day"], [3600, "hour"], [60, "minute"]] as const) {
    if (secs >= size) {
      const n = Math.floor(secs / size)
      return `${n} ${unit}${n === 1 ? "" : "s"} ago`
    }
  }
  return ""
}

export function clock(ts: string | null | undefined): string {
  const date = parse(ts)
  return date
    ? date.toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit" })
    : ""
}

export function factLabel(key: string): string {
  return sentence(key.replaceAll("_", " ").replace(/\bpass\b/, "passed").replace(/\bip\b/, "IP").replace(/\bips\b/, "IPs"))
}

export function factValue(value: unknown): string {
  if (value === true) return "Yes"
  if (value === false) return "No"
  if (Array.isArray(value)) return value.join(", ")
  if (value && typeof value === "object") return JSON.stringify(value)
  return String(value)
}
