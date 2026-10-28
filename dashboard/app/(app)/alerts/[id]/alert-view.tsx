"use client"

import Link from "next/link"
import { useParams } from "next/navigation"
import { ChevronLeft, ClipboardCheck } from "lucide-react"

import { Dot, LoadError, LoadMore, Loading, Quarantined, ToneBadge } from "@/components/tg/bits"
import { EventList } from "@/components/tg/events"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { usePaged, useTg } from "@/lib/api"
import { ALERT_STATUS, clock, factLabel, factValue, FLAG_LABELS, sentence, tierOf, toolLabel, type Tone } from "@/lib/format"
import type { Alert, AuditRecord, Escalation } from "@/lib/types"

export function AlertView() {
  const id = decodeURIComponent(useParams<{ id: string }>().id)
  const q = encodeURIComponent(id)
  const alert = useTg<Alert>(`/v1/alerts/${q}`)
  const audit = usePaged<AuditRecord>(`/v1/audit?alert_id=${q}&limit=100`)
  const held = usePaged<Escalation>(`/v1/escalations?status=open&alert_id=${q}&limit=50`)
  const review = `/review?alert=${q}`

  const back = (
    <Button asChild variant="ghost" size="sm" className="mb-4 -ml-2 text-muted-foreground">
      <Link href="/alerts">
        <ChevronLeft /> Alerts
      </Link>
    </Button>
  )
  if (alert.error) return (<>{back}<LoadError error={alert.error} /></>)
  if (!alert.data) return (<>{back}<Loading rows={3} /></>)

  const a = alert.data
  const facts = Object.entries(a.facts).filter(([, v]) => v !== null && !(Array.isArray(v) && v.length === 0))
  const flagged = a.evidence.filter((e) => e.flags.length > 0)
  const raised = a.original_severity && a.original_severity !== a.severity ? a.original_severity : null
  const waiting = held.items ?? []
  const waitingCount = held.total ?? waiting.length
  const intake: { text: string; meta: string; tone: Tone }[] = [
    { text: `Received from the ${a.source} feed`, meta: clock(a.received_at), tone: "neutral" },
    {
      text: `Split into ${facts.length} trusted facts and ${a.evidence.length} pieces of untrusted content${flagged.length ? ` — ${flagged.length} flagged` : ""}`,
      meta: "Facts come from parsers and lookups; the rest is treated as attacker-written",
      tone: "info",
    },
  ]
  if (a.tags.includes("AI-evasion attempt")) {
    intake.push({
      text: `Found text aimed at the AI: tagged as an AI-evasion attempt${raised ? ` and severity raised from ${raised} to ${a.severity}` : ""}`,
      meta: "Untrusted text can raise suspicion but never lower it",
      tone: "danger",
    })
  }

  return (
    <>
      {back}
      <div className="mb-8">
        <h1 className="text-3xl font-semibold tracking-tight">Alert {a.alert_id}</h1>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <ToneBadge tone="neutral">{sentence(a.source)}</ToneBadge>
          <ToneBadge tone={a.severity === "critical" ? "danger" : "warning"}>
            {sentence(a.severity)} severity{raised ? ` (was ${raised})` : ""}
          </ToneBadge>
          {a.tags.map((t) => (
            <ToneBadge key={t} tone="danger">
              {sentence(t)}
            </ToneBadge>
          ))}
          {a.status && <ToneBadge tone={ALERT_STATUS[a.status].tone}>{ALERT_STATUS[a.status].label}</ToneBadge>}
        </div>
      </div>

      {waitingCount > 0 && (
        <Card className="mb-6 gap-0 border-warning/40 bg-warning/5 py-0 shadow-none">
          <CardContent className="flex flex-col gap-4 px-5 py-4 sm:flex-row sm:items-center">
            <div className="min-w-0 flex-1">
              <div className="text-[15px] font-medium">
                {waitingCount === 1 ? "1 action is" : `${waitingCount} actions are`} waiting for your decision
              </div>
              <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-[13px] text-muted-foreground">
                {waiting.map((e) => (
                  <span key={e.id} className="flex items-center gap-1.5">
                    <Dot tone={tierOf(e.tier).tone} />
                    {toolLabel(e.tool)}
                  </span>
                ))}
              </div>
            </div>
            <Button asChild>
              <Link href={review}>
                <ClipboardCheck /> Review now
              </Link>
            </Button>
          </CardContent>
        </Card>
      )}

      <Tabs defaultValue="steps">
        <TabsList className="mb-4">
          <TabsTrigger value="steps">Every step</TabsTrigger>
          <TabsTrigger value="facts">Trusted facts</TabsTrigger>
          <TabsTrigger value="content">Untrusted content</TabsTrigger>
        </TabsList>

        <TabsContent value="steps">
          <Card className="shadow-none">
            <CardHeader>
              <CardTitle className="text-lg">From arrival to outcome</CardTitle>
              <CardDescription>Each step TrustGate took for this alert, oldest first.</CardDescription>
            </CardHeader>
            <CardContent>
              <ol className="mb-5 flex flex-col gap-5">
                {intake.map((s) => (
                  <li key={s.text} className="flex gap-3.5">
                    <Dot tone={s.tone} className="mt-1.5" />
                    <div>
                      <div className="text-[14.5px] leading-snug">{s.text}</div>
                      <div className="mt-0.5 text-xs text-muted-foreground">{s.meta}</div>
                    </div>
                  </li>
                ))}
              </ol>
              {!audit.items ? (
                <Loading rows={2} />
              ) : audit.items.length === 0 ? (
                <p className="text-sm text-muted-foreground">The AI agent hasn&apos;t worked on this alert yet.</p>
              ) : (
                <EventList records={audit.items} />
              )}
              <LoadMore hasMore={audit.hasMore} loading={audit.loadingMore} onClick={audit.loadMore} />
              {waiting.map((e) => (
                <Link key={e.id} href={review} className="mt-5 flex items-center gap-3.5 rounded-xl border border-warning/40 bg-warning/5 px-4 py-3 hover:bg-warning/10">
                  <Dot tone="warning" />
                  <span className="text-[14.5px]">
                    Waiting for an analyst: <b className="font-medium">{toolLabel(e.tool)}</b>
                  </span>
                  <span className="ml-auto text-xs text-muted-foreground">Open review queue</span>
                </Link>
              ))}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="facts">
          <Card className="py-0 shadow-none">
            <CardHeader className="pt-6">
              <CardDescription>Produced by parsers and threat-intel lookups. An attacker can&apos;t write these.</CardDescription>
            </CardHeader>
            <Table>
              <TableBody>
                {facts.map(([k, v]) => (
                  <TableRow key={k} className="hover:bg-transparent">
                    <TableCell className="w-1/2 pl-6 text-muted-foreground">{factLabel(k)}</TableCell>
                    <TableCell className="pr-6 font-medium break-all whitespace-normal">{factValue(v)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
        </TabsContent>

        <TabsContent value="content">
          <Card className="shadow-none">
            <CardHeader>
              <CardDescription>
                Written by whoever sent the alert. Shown as plain text and never followed as instructions.
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-5">
              {a.evidence.map((e) => (
                <div key={e.id}>
                  <div className="mb-1.5 flex flex-wrap items-center gap-2 text-sm">
                    <span className="font-medium">{e.id}</span>
                    <span className="text-muted-foreground">{e.field}</span>
                    {e.flags.map((f) => (
                      <ToneBadge key={f} tone="danger">
                        {FLAG_LABELS[f] ?? sentence(f.replaceAll("_", " "))}
                      </ToneBadge>
                    ))}
                  </div>
                  <Quarantined>{e.content}</Quarantined>
                </div>
              ))}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </>
  )
}
