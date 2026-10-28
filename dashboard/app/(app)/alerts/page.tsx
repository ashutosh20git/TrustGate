"use client"

import { useDeferredValue, useState } from "react"
import Link from "next/link"
import { ChevronRight, ClipboardCheck, Inbox, Search } from "lucide-react"

import { EmptyState, LoadError, LoadMore, Loading, PageHeader, ToneBadge } from "@/components/tg/bits"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { usePaged, useTg } from "@/lib/api"
import { ago, ALERT_STATUS as STATUS, sentence } from "@/lib/format"
import type { AlertCounts, AlertSummary } from "@/lib/types"

const FILTERS = ["all", "waiting", "handled", "new"] as const
type Filter = (typeof FILTERS)[number]

export default function AlertsPage() {
  const [filter, setFilter] = useState<Filter>("all")
  const [query, setQuery] = useState("")
  const q = useDeferredValue(query.trim())
  const params = new URLSearchParams({ limit: "50" })
  if (filter !== "all") params.set("status", filter)
  if (q) params.set("q", q)
  const alerts = usePaged<AlertSummary>(`/v1/alerts?${params}`)
  const counts = useTg<AlertCounts>("/v1/alert-counts")
  const empty = counts.data?.all === 0

  return (
    <>
      <PageHeader title="Alerts" description="Everything TrustGate received. Open an alert to see every step, from arrival to outcome." />
      {alerts.error ? (
        <LoadError error={alerts.error} />
      ) : empty ? (
        <Card className="shadow-none">
          <EmptyState icon={<Inbox />} title="No alerts yet" description="Alerts appear here when your SIEM or mail gateway sends them." />
        </Card>
      ) : (
        <>
          <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <ToggleGroup
              type="single"
              variant="outline"
              value={filter}
              onValueChange={(v) => v && setFilter(v as Filter)}
              className="flex-wrap"
            >
              {FILTERS.map((f) => (
                <ToggleGroupItem key={f} value={f} className="px-3 text-[13px]">
                  {f === "all" ? "All" : STATUS[f].label}
                  <span className="ml-1 text-muted-foreground tabular-nums">{counts.data?.[f] ?? ""}</span>
                </ToggleGroupItem>
              ))}
            </ToggleGroup>
            <div className="relative sm:w-64">
              <Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input placeholder="Search by alert ID" value={query} onChange={(e) => setQuery(e.target.value)} className="h-9 pl-9" />
            </div>
          </div>
          {!alerts.items ? (
            <Loading rows={4} />
          ) : (
            <Card className="overflow-hidden py-0 shadow-none">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="pl-5">Alert</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="hidden md:table-cell">Warnings</TableHead>
                    <TableHead className="hidden sm:table-cell">Received</TableHead>
                    <TableHead className="w-8" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {alerts.items.map((a) => {
                    const href = `/alerts/${encodeURIComponent(a.alert_id)}`
                    return (
                      <TableRow key={a.alert_id} className="group relative h-14 cursor-pointer">
                        <TableCell className="pl-5 font-medium">
                          <Link href={href} className="after:absolute after:inset-0">
                            {a.alert_id}
                          </Link>
                        </TableCell>
                        <TableCell>{sentence(a.source)}</TableCell>
                        <TableCell>
                          <span className={a.severity === "critical" ? "font-medium text-danger" : ""}>{sentence(a.severity)}</span>
                          {a.original_severity && a.original_severity !== a.severity && (
                            <span className="ml-1 text-xs text-muted-foreground">from {a.original_severity}</span>
                          )}
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <ToneBadge tone={STATUS[a.status].tone}>{STATUS[a.status].label}</ToneBadge>
                            {a.status === "waiting" && (
                              // Above the row link, so it opens the queue instead of the alert.
                              <Button asChild variant="outline" size="sm" className="relative z-10 h-7">
                                <Link href={`/review?alert=${encodeURIComponent(a.alert_id)}`}>
                                  <ClipboardCheck /> Review
                                </Link>
                              </Button>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="hidden md:table-cell">
                          <div className="flex flex-wrap gap-1">
                            {a.tags.length === 0 ? (
                              <span className="text-muted-foreground">—</span>
                            ) : (
                              a.tags.map((t) => (
                                <ToneBadge key={t} tone="danger">
                                  {sentence(t)}
                                </ToneBadge>
                              ))
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="hidden text-muted-foreground sm:table-cell">{ago(a.received_at)}</TableCell>
                        <TableCell>
                          <ChevronRight className="size-4 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
                        </TableCell>
                      </TableRow>
                    )
                  })}
                  {alerts.items.length === 0 && (
                    <TableRow className="hover:bg-transparent">
                      <TableCell colSpan={7} className="py-10 text-center text-muted-foreground">
                        No alerts match.
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </Card>
          )}
          <LoadMore hasMore={alerts.hasMore} loading={alerts.loadingMore} onClick={alerts.loadMore} />
        </>
      )}
    </>
  )
}
