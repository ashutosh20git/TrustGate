"use client"

import { Suspense, useState } from "react"
import Link from "next/link"
import { useRouter, useSearchParams } from "next/navigation"
import { ArrowLeft, CheckCircle2, History, Loader2, X } from "lucide-react"
import { toast } from "sonner"

import { EmptyState, LoadError, LoadMore, Loading, PageHeader, Quarantined, ToneBadge } from "@/components/tg/bits"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader } from "@/components/ui/card"
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { send, usePaged, useTg } from "@/lib/api"
import { ago, factLabel, plainReason, sentence, tierOf, toolLabel, type Tone } from "@/lib/format"
import type { Alert, Escalation, Explanation } from "@/lib/types"

const OUTCOME: Record<string, { label: string; tone: Tone }> = {
  approved: { label: "Approved", tone: "success" },
  rejected: { label: "Rejected", tone: "neutral" },
  failed: { label: "Approved, but it failed to run", tone: "danger" },
  expired: { label: "Expired", tone: "neutral" },
}

const HEADER = (
  <PageHeader
    title="Review queue"
    description="Actions TrustGate held back. Nothing here has run yet: approve to run it, or reject to drop it."
  />
)

// ?alert= narrows the queue to one alert; reading it needs a Suspense boundary.
export default function ReviewPage() {
  return (
    <Suspense
      fallback={
        <>
          {HEADER}
          <Loading rows={2} />
        </>
      }
    >
      <Review />
    </Suspense>
  )
}

function Review() {
  const router = useRouter()
  const alert = useSearchParams().get("alert")
  const [tab, setTab] = useState("waiting")
  const only = alert ? `&alert_id=${encodeURIComponent(alert)}` : ""
  const queue = usePaged<Escalation>(`/v1/escalations?status=open&limit=20${only}`)
  const decided = usePaged<Escalation>(tab === "decided" ? `/v1/escalations?status=decided&limit=20${only}` : null)
  const [deciding, setDeciding] = useState<{ esc: Escalation; approve: boolean } | null>(null)
  const alertHref = alert ? `/alerts/${encodeURIComponent(alert)}` : "/alerts"

  return (
    <>
      {HEADER}
      {alert && (
        <div className="mb-5 flex flex-wrap items-center gap-2 rounded-xl border bg-card px-4 py-2.5 text-sm">
          <span>
            Showing only alert <b className="font-medium">{alert}</b>
          </span>
          <div className="ml-auto flex gap-2">
            <Button asChild variant="ghost" size="sm">
              <Link href={alertHref}>
                <ArrowLeft /> Back to alert
              </Link>
            </Button>
            <Button variant="outline" size="sm" onClick={() => router.replace("/review")}>
              <X /> Show whole queue
            </Button>
          </div>
        </div>
      )}
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList className="mb-5">
          <TabsTrigger value="waiting">
            Waiting
            {queue.total != null && <span className="ml-1 text-muted-foreground tabular-nums">{queue.total}</span>}
          </TabsTrigger>
          <TabsTrigger value="decided">Decided</TabsTrigger>
        </TabsList>

        <TabsContent value="waiting">
          {queue.error ? (
            <LoadError error={queue.error} />
          ) : !queue.items ? (
            <Loading rows={2} />
          ) : queue.items.length === 0 ? (
            <Card className="shadow-none">
              {alert ? (
                <div className="flex flex-col items-center pb-10">
                  <EmptyState
                    icon={<CheckCircle2 />}
                    title={`Alert ${alert} is done`}
                    description="Nothing for this alert is waiting any more."
                  />
                  <div className="-mt-6 flex gap-2">
                    <Button asChild variant="outline">
                      <Link href={alertHref}>Back to alert</Link>
                    </Button>
                    <Button onClick={() => router.replace("/review")}>Rest of the queue</Button>
                  </div>
                </div>
              ) : (
                <EmptyState icon={<CheckCircle2 />} title="All clear" description="Nothing is waiting for a decision." />
              )}
            </Card>
          ) : (
            <div className="flex flex-col gap-5">
              {queue.items.map((e) => (
                <ReviewCard key={e.id} esc={e} onDecide={(approve) => setDeciding({ esc: e, approve })} />
              ))}
            </div>
          )}
          <LoadMore hasMore={queue.hasMore} loading={queue.loadingMore} onClick={queue.loadMore} />
        </TabsContent>

        <TabsContent value="decided">
          {decided.error ? (
            <LoadError error={decided.error} />
          ) : !decided.items ? (
            <Loading rows={3} />
          ) : decided.items.length === 0 ? (
            <Card className="shadow-none">
              <EmptyState icon={<History />} title="No decisions yet" description="Approved and rejected actions are kept here for good." />
            </Card>
          ) : (
            <Card className="divide-y gap-0 py-0 shadow-none">
              {decided.items.map((e) => (
                <DecidedRow key={e.id} esc={e} />
              ))}
            </Card>
          )}
          <LoadMore hasMore={decided.hasMore} loading={decided.loadingMore} onClick={decided.loadMore} />
        </TabsContent>
      </Tabs>
      <DecideDialog
        state={deciding}
        onClose={() => setDeciding(null)}
        onDone={() => {
          setDeciding(null)
          queue.mutate()
        }}
      />
    </>
  )
}

function DecidedRow({ esc }: { esc: Escalation }) {
  const outcome = OUTCOME[esc.status] ?? { label: sentence(esc.status), tone: "neutral" as Tone }
  return (
    <div className="flex flex-col gap-1 px-5 py-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[15px] font-medium">{toolLabel(esc.tool)}</span>
        <ToneBadge tone={outcome.tone}>{outcome.label}</ToneBadge>
        <ToneBadge tone={tierOf(esc.tier).tone}>{tierOf(esc.tier).label}</ToneBadge>
      </div>
      <div className="text-[13px] text-muted-foreground">
        <Link href={`/alerts/${encodeURIComponent(esc.alert_id)}`} className="hover:text-foreground">
          alert {esc.alert_id}
        </Link>
        {esc.analyst && ` · by ${esc.analyst}`} · {ago(esc.decided_at ?? esc.created_at)}
      </div>
      {esc.analyst_reason && <div className="text-[13.5px] text-foreground/80">“{esc.analyst_reason}”</div>}
    </div>
  )
}

function ReviewCard({ esc, onDecide }: { esc: Escalation; onDecide: (approve: boolean) => void }) {
  const why = useTg<Explanation>(`/v1/escalations/${esc.id}/explain`, { refreshInterval: 0 })
  const alert = useTg<Alert>(esc.tainted_spans.length ? `/v1/alerts/${encodeURIComponent(esc.alert_id)}` : null, {
    refreshInterval: 0,
  })
  const tier = tierOf(esc.tier)
  const evidence = new Map((alert.data?.evidence ?? []).map((e) => [e.id, e]))
  const args = Object.entries(esc.action.args ?? {})

  return (
    <Card className="gap-0 shadow-none">
      <CardHeader className="gap-2 pb-5">
        <div className="flex flex-wrap items-center gap-2 text-[13px] text-muted-foreground">
          <ToneBadge tone={tier.tone}>{tier.label}</ToneBadge>
          <span>
            alert {esc.alert_id} · {ago(esc.created_at)}
          </span>
        </div>
        <h2 className="text-xl font-semibold tracking-tight">The AI wants to: {toolLabel(esc.tool)}</h2>
        {esc.reasons[0] && <p className="text-[15px] text-foreground/80">{plainReason(esc.reasons[0])}</p>}
      </CardHeader>
      <Separator />
      <CardContent className="grid gap-8 pt-5 lg:grid-cols-[1fr_320px]">
        <div className="flex flex-col gap-5 text-[14px]">
          {esc.reasons.length > 1 && (
            <section>
              <h3 className="mb-2 text-[13px] font-semibold text-muted-foreground uppercase">Every reason it was held</h3>
              <ul className="flex flex-col gap-1.5">
                {esc.reasons.map((r) => (
                  <li key={r} title={r} className="flex gap-2">
                    <span className="mt-2 size-1 shrink-0 rounded-full bg-muted-foreground" />
                    {plainReason(r)}
                  </li>
                ))}
              </ul>
            </section>
          )}
          {why.data && (why.data.would_allow_if.length > 0 || why.data.never_automatic.length > 0) && (
            <section className="flex flex-col gap-2">
              {why.data.would_allow_if.map((c) => (
                <div key={c} className="rounded-lg bg-success/8 px-3 py-2 text-success">
                  Would run automatically if {c}
                </div>
              ))}
              {why.data.never_automatic.map((c) => (
                <div key={c} className="rounded-lg bg-warning/10 px-3 py-2 text-foreground/80">
                  <span className="font-medium text-warning">Always needs a human:</span> {c}
                </div>
              ))}
            </section>
          )}
          {esc.tainted_spans.length > 0 && (
            <section>
              <h3 className="mb-2 text-[13px] font-semibold text-muted-foreground uppercase">Untrusted content that influenced it</h3>
              <div className="flex flex-col gap-3">
                {esc.tainted_spans.map((span) => {
                  const ev = evidence.get(span)
                  return (
                    <div key={span}>
                      <div className="mb-1 text-xs text-muted-foreground">
                        {span}
                        {ev ? ` · ${ev.field}` : ""}
                      </div>
                      {ev && <Quarantined>{ev.content}</Quarantined>}
                    </div>
                  )
                })}
              </div>
            </section>
          )}
        </div>
        <aside className="flex flex-col gap-4">
          <div className="rounded-xl border bg-muted/30">
            <dl className="divide-y text-[13.5px]">
              {[
                ["Action", toolLabel(esc.tool)],
                ["AI's verdict", sentence(esc.action.verdict)],
                ["Cites", esc.action.cited_evidence.join(", ") || "nothing"],
                ...args.map(([k, v]) => [factLabel(k), String(v)]),
              ].map(([k, v]) => (
                <div key={k} className="flex gap-3 px-3.5 py-2.5">
                  <dt className="w-24 shrink-0 text-muted-foreground">{k}</dt>
                  <dd className="min-w-0 font-medium break-words">{v}</dd>
                </div>
              ))}
            </dl>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <Button variant="outline" onClick={() => onDecide(false)}>
              Reject
            </Button>
            <Button onClick={() => onDecide(true)}>Approve</Button>
          </div>
        </aside>
      </CardContent>
    </Card>
  )
}

function DecideDialog({
  state,
  onClose,
  onDone,
}: {
  state: { esc: Escalation; approve: boolean } | null
  onClose: () => void
  onDone: () => void
}) {
  const [reason, setReason] = useState("")
  const [second, setSecond] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const esc = state?.esc
  const approve = state?.approve ?? false
  const needsSecond = approve && (esc?.tier ?? 0) >= 2

  function reset() {
    setReason("")
    setSecond("")
    setError(null)
    setBusy(false)
  }

  async function confirm() {
    if (!esc) return
    setBusy(true)
    setError(null)
    const err = await send(`/v1/escalations/${esc.id}/${approve ? "approve" : "reject"}`, { reason }, second.trim() || undefined)
    if (err) {
      setError(err)
      setBusy(false)
      return
    }
    toast.success(approve ? "Approved — the action ran." : "Rejected — the action was dropped.")
    reset()
    onDone()
  }

  return (
    <Dialog
      open={!!state}
      onOpenChange={(open) => {
        if (!open) {
          reset()
          onClose()
        }
      }}
    >
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{approve ? "Approve and run this action?" : "Reject this action?"}</DialogTitle>
          <DialogDescription>
            {esc && (
              <>
                {toolLabel(esc.tool)} on alert {esc.alert_id}.{" "}
                {approve ? "TrustGate checks it again right before it runs." : "It will not run."}
              </>
            )}
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            <Label htmlFor="reason">Reason</Label>
            <Textarea id="reason" placeholder="Why are you making this decision?" value={reason} onChange={(e) => setReason(e.target.value)} />
          </div>
          {needsSecond && (
            <div className="flex flex-col gap-2">
              <Label htmlFor="second">Second analyst&apos;s token</Label>
              <Input id="second" type="password" autoComplete="off" value={second} onChange={(e) => setSecond(e.target.value)} />
              <p className="text-xs text-muted-foreground">
                This action is disruptive or sends data out, so a second, different analyst must approve it too.
              </p>
            </div>
          )}
          {error && <p className="rounded-lg bg-danger/8 px-3 py-2 text-sm text-danger">{error}</p>}
        </div>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <Button
            variant={approve ? "default" : "destructive"}
            disabled={busy || !reason.trim() || (needsSecond && !second.trim())}
            onClick={confirm}
          >
            {busy && <Loader2 className="animate-spin" />}
            {approve ? "Approve" : "Reject"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
