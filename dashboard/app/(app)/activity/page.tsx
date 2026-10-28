"use client"

import { useDeferredValue, useMemo, useState } from "react"
import Link from "next/link"
import { Download, History, Loader2, Search } from "lucide-react"
import { toast } from "sonner"

import { Dot, EmptyState, LoadError, LoadMore, Loading, PageHeader, ToneBadge } from "@/components/tg/bits"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { fetchAll, usePaged } from "@/lib/api"
import { clock, describe, EVENT_KINDS, plainReason, tierOf } from "@/lib/format"
import type { AuditRecord } from "@/lib/types"

const ALL = "__all__"

export default function ActivityPage() {
  const [alertId, setAlertId] = useState("")
  const [kind, setKind] = useState(ALL)
  const [open, setOpen] = useState<AuditRecord | null>(null)
  const [downloading, setDownloading] = useState(false)
  const alert = useDeferredValue(alertId.trim())

  const params = new URLSearchParams({ newest: "true" })
  if (alert) params.set("alert_id", alert)
  if (kind !== ALL) params.set("kind", kind)
  const audit = usePaged<AuditRecord>(`/v1/audit?${params}&limit=50`)
  // Pages walk back from the newest record; show newest first by chain position.
  const records = useMemo(() => [...(audit.items ?? [])].sort((a, b) => b.seq - a.seq), [audit.items])
  const filtered = alert !== "" || kind !== ALL

  async function download() {
    setDownloading(true)
    try {
      const all = await fetchAll<AuditRecord>(`/v1/audit?${params}&limit=5000`)
      const blob = new Blob([JSON.stringify(all.sort((a, b) => a.seq - b.seq), null, 2)], { type: "application/json" })
      const link = document.createElement("a")
      link.href = URL.createObjectURL(blob)
      link.download = "trustgate-activity.json"
      link.click()
      URL.revokeObjectURL(link.href)
    } catch {
      toast.error("Couldn't download the log.")
    } finally {
      setDownloading(false)
    }
  }

  return (
    <>
      <PageHeader
        title="Activity log"
        description="Every step TrustGate recorded, newest first. Each entry is chained to the one before it, so any change to the log is detectable."
      >
        <Button variant="outline" onClick={download} disabled={!records.length || downloading}>
          {downloading ? <Loader2 className="animate-spin" /> : <Download />} Download
        </Button>
      </PageHeader>
      <div className="mb-4 flex flex-wrap gap-3">
        <div className="relative w-48">
          <Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input placeholder="Alert ID" value={alertId} onChange={(e) => setAlertId(e.target.value)} className="h-9 pl-9" />
        </div>
        <Select value={kind} onValueChange={setKind}>
          <SelectTrigger className="w-52">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>All kinds of events</SelectItem>
            {Object.entries(EVENT_KINDS).map(([k, label]) => (
              <SelectItem key={k} value={k}>
                {label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      {audit.error ? (
        <LoadError error={audit.error} />
      ) : !audit.items ? (
        <Loading rows={5} />
      ) : records.length === 0 ? (
        <Card className="shadow-none">
          {filtered ? (
            <EmptyState icon={<History />} title="No matching events" description="Try another alert ID or kind of event." />
          ) : (
            <EmptyState icon={<History />} title="Nothing recorded yet" description="Every decision and action will be listed here." />
          )}
        </Card>
      ) : (
        <>
          <Card className="gap-0 divide-y py-0 shadow-none">
            {records.map((r) => {
              const { text, tone } = describe(r)
              return (
                <button
                  key={r.id}
                  onClick={() => setOpen(r)}
                  className="flex w-full items-start gap-3.5 px-5 py-3.5 text-left transition-colors hover:bg-muted/50"
                >
                  <Dot tone={tone} className="mt-1.5" />
                  <div className="min-w-0 flex-1">
                    <div className="text-[14.5px] leading-snug">{text}</div>
                    <div className="mt-0.5 text-xs text-muted-foreground">
                      {clock(r.ts)}
                      {r.alert_id ? ` · alert ${r.alert_id}` : ""}
                      {r.reasons.length && r.decision !== "allow" ? ` · ${plainReason(r.reasons[0])}` : ""}
                    </div>
                  </div>
                  {r.tier != null && <ToneBadge tone={tierOf(r.tier).tone} className="hidden sm:inline-flex">{tierOf(r.tier).label}</ToneBadge>}
                </button>
              )
            })}
          </Card>
          <LoadMore hasMore={audit.hasMore} loading={audit.loadingMore} onClick={audit.loadMore} />
        </>
      )}
      <Sheet open={!!open} onOpenChange={(o) => !o && setOpen(null)}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-lg">
          {open && (
            <>
              <SheetHeader>
                <SheetTitle className="text-lg leading-snug">{describe(open).text}</SheetTitle>
                <SheetDescription>
                  {clock(open.ts)} · entry #{open.seq}
                </SheetDescription>
              </SheetHeader>
              <div className="flex flex-col gap-5 px-4 pb-6 text-sm">
                {open.alert_id && (
                  <Button asChild variant="outline" size="sm" className="w-fit">
                    <Link href={`/alerts/${encodeURIComponent(open.alert_id)}`}>Open alert {open.alert_id}</Link>
                  </Button>
                )}
                {open.reasons.length > 0 && (
                  <section>
                    <h3 className="mb-2 text-[13px] font-semibold text-muted-foreground uppercase">Reasons</h3>
                    <ul className="flex flex-col gap-2">
                      {open.reasons.map((r) => (
                        <li key={r}>
                          {plainReason(r)}
                          <div className="font-mono text-xs text-muted-foreground">{r}</div>
                        </li>
                      ))}
                    </ul>
                  </section>
                )}
                <section>
                  <h3 className="mb-2 text-[13px] font-semibold text-muted-foreground uppercase">Exact record</h3>
                  <pre className="overflow-auto rounded-lg border bg-muted/50 p-3 font-mono text-xs leading-relaxed">
                    {JSON.stringify(open, null, 2)}
                  </pre>
                </section>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </>
  )
}
