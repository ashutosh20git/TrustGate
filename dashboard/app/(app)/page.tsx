"use client"

import Link from "next/link"
import { ArrowRight, CheckCircle2, Inbox } from "lucide-react"
import { Bar, BarChart, CartesianGrid, XAxis, YAxis } from "recharts"

import { Dot, EmptyState, LoadError, Loading, PageHeader, Stat, ToneBadge } from "@/components/tg/bits"
import { EventList } from "@/components/tg/events"
import { Button } from "@/components/ui/button"
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { ChartContainer, ChartLegend, ChartLegendContent, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart"
import { usePaged, useTg } from "@/lib/api"
import { ago, plainReason, tierOf, TIERS, toolLabel } from "@/lib/format"
import type { AuditRecord, Escalation, Metrics } from "@/lib/types"

const chartConfig = {
  allowed: { label: "Allowed", color: "var(--success)" },
  held: { label: "Held for review", color: "var(--warning)" },
  blocked: { label: "Blocked", color: "var(--danger)" },
} satisfies ChartConfig

export default function OverviewPage() {
  const metrics = useTg<Metrics>("/v1/metrics")
  const open = usePaged<Escalation>("/v1/escalations?status=open&limit=5")
  const recent = useTg<AuditRecord[]>("/v1/audit?limit=8&newest=true")

  if (metrics.error) return <LoadError error={metrics.error} />
  const m = metrics.data
  const by = m?.by_tier_decision ?? {}
  const sum = (test: (key: string) => boolean) => Object.entries(by).reduce((n, [k, v]) => n + (test(k) ? v : 0), 0)
  const allowed = sum((k) => k.endsWith(":allow") && !k.startsWith("T0"))
  const held = sum((k) => !k.endsWith(":allow"))
  const waiting = open.total ?? m?.escalations?.open ?? 0
  const agreement = m?.recheck_analyst_agreement?.agreement_rate

  const chart = Object.entries(TIERS).map(([tier, info]) => ({
    tier: info.label,
    allowed: by[`T${tier}:allow`] ?? 0,
    held: by[`T${tier}:escalate`] ?? 0,
    blocked: by[`T${tier}:block`] ?? 0,
  }))

  return (
    <>
      <PageHeader title="Overview" description="What the AI agent tried, what TrustGate decided, and what needs you." />
      {!m ? (
        <Loading rows={2} />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Stat label="Alerts received" value={m.alerts} hint={`${m.ai_evasion_alerts} tried to manipulate the AI`} />
            <Stat label="Waiting for you" value={waiting} hint="actions held for a human" highlight={waiting > 0} />
            <Stat label="Security actions allowed" value={allowed} hint="ran without a human" />
            <Stat label="Actions held back" value={held} hint="escalated or blocked" />
          </div>
          <div className="mt-4 grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Stat small label="Mode" value={m.mode === "enforce" ? "Enforcing" : "Monitor only"} hint={`${m.pack} policy pack`} />
            <Stat small label="Audit log" value={m.audit_chain_ok ? "Intact" : "Broken"} hint="tamper-evident chain" />
            <Stat small label="Checks that failed safe" value={m.fail_closed} hint="errors or timeouts, held" />
            <Stat
              small
              label="Decision time (p95)"
              value={`${Math.round(m.latency_ms_p95 ?? 0)} ms`}
              hint={`fact check agrees with analysts ${agreement == null ? "—" : `${Math.round(agreement * 100)}%`}`}
            />
          </div>
        </>
      )}

      <div className="mt-8 grid gap-6 lg:grid-cols-2">
        <Card className="shadow-none">
          <CardHeader>
            <CardTitle className="text-lg">Needs your attention</CardTitle>
            <CardDescription>Actions TrustGate held for a human decision.</CardDescription>
            {waiting > 0 && (
              <CardAction>
                <Button asChild variant="ghost" size="sm">
                  <Link href="/review">
                    Review all <ArrowRight />
                  </Link>
                </Button>
              </CardAction>
            )}
          </CardHeader>
          <CardContent>
            {!open.items ? (
              <Loading rows={2} />
            ) : open.items.length === 0 ? (
              <EmptyState icon={<CheckCircle2 />} title="All clear" description="Nothing is waiting for a decision." />
            ) : (
              <ul className="flex flex-col divide-y">
                {open.items.map((e) => (
                    <li key={e.id}>
                      <Link href={`/review?alert=${encodeURIComponent(e.alert_id)}`} className="-mx-2 flex items-start gap-3 rounded-lg px-2 py-3 hover:bg-muted/60">
                        <Dot tone="warning" className="mt-1.5" />
                        <div className="min-w-0 flex-1">
                          <div className="text-[14.5px] font-medium">
                            {toolLabel(e.tool)} <span className="font-normal text-muted-foreground">· alert {e.alert_id}</span>
                          </div>
                          <div className="mt-0.5 truncate text-[13px] text-muted-foreground">
                            {e.reasons[0] ? plainReason(e.reasons[0]) : ""}
                          </div>
                        </div>
                        <div className="flex shrink-0 flex-col items-end gap-1">
                          <ToneBadge tone={tierOf(e.tier).tone}>{tierOf(e.tier).label}</ToneBadge>
                          <span className="text-xs text-muted-foreground">{ago(e.created_at)}</span>
                        </div>
                      </Link>
                    </li>
                  ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card className="shadow-none">
          <CardHeader>
            <CardTitle className="text-lg">Recent activity</CardTitle>
            <CardDescription>The latest steps, newest first.</CardDescription>
            <CardAction>
              <Button asChild variant="ghost" size="sm">
                <Link href="/activity">
                  Full log <ArrowRight />
                </Link>
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent>
            {!recent.data ? (
              <Loading rows={3} />
            ) : recent.data.length === 0 ? (
              <EmptyState icon={<Inbox />} title="No activity yet" description="Decisions appear here as the AI agent works." />
            ) : (
              <EventList records={[...recent.data].reverse()} showAlert compact />
            )}
          </CardContent>
        </Card>
      </div>

      {m && m.decisions > 0 && (
        <Card className="mt-6 shadow-none">
          <CardHeader>
            <CardTitle className="text-lg">Decisions by kind of action</CardTitle>
            <CardDescription>Read-only work runs freely; anything that lowers security has to prove itself.</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={chartConfig} className="h-64 w-full">
              <BarChart data={chart} margin={{ left: -16 }}>
                <CartesianGrid vertical={false} />
                <XAxis dataKey="tier" tickLine={false} axisLine={false} tickMargin={10} />
                <YAxis allowDecimals={false} tickLine={false} axisLine={false} />
                <ChartTooltip cursor={false} content={<ChartTooltipContent />} />
                <ChartLegend content={<ChartLegendContent />} />
                <Bar dataKey="allowed" stackId="a" fill="var(--color-allowed)" isAnimationActive={false} />
                <Bar dataKey="held" stackId="a" fill="var(--color-held)" isAnimationActive={false} />
                <Bar dataKey="blocked" stackId="a" fill="var(--color-blocked)" radius={[6, 6, 0, 0]} isAnimationActive={false} />
              </BarChart>
            </ChartContainer>
          </CardContent>
        </Card>
      )}
    </>
  )
}
