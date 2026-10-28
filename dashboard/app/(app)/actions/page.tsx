"use client"

import { useState } from "react"
import Link from "next/link"
import { Undo2, Zap } from "lucide-react"

import { EmptyState, LoadError, LoadMore, Loading, PageHeader, ToneBadge } from "@/components/tg/bits"
import { ReasonDialog } from "@/components/tg/reason-dialog"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { usePaged } from "@/lib/api"
import { ago, sentence, tierOf, toolLabel, type Tone } from "@/lib/format"
import type { ActionRecord } from "@/lib/types"

const VIA: Record<string, string> = {
  gate: "Automatically",
  approval: "Approved by an analyst",
  mcp_gateway: "Through the MCP gateway",
}
const STATUS: Record<string, { label: string; tone: Tone }> = {
  executed: { label: "Done", tone: "info" },
  reverted: { label: "Undone", tone: "violet" },
  revert_failed: { label: "Undo failed", tone: "danger" },
}

export default function ActionsPage() {
  const actions = usePaged<ActionRecord>("/v1/actions?limit=50")
  const [undoing, setUndoing] = useState<ActionRecord | null>(null)

  return (
    <>
      <PageHeader title="Actions taken" description="Everything TrustGate carried out that changes your security. Each one can be undone." />
      {actions.error ? (
        <LoadError error={actions.error} />
      ) : !actions.items ? (
        <Loading rows={3} />
      ) : actions.items.length === 0 ? (
        <Card className="shadow-none">
          <EmptyState icon={<Zap />} title="No actions yet" description="Security-changing actions appear here once they run." />
        </Card>
      ) : (
        <Card className="divide-y gap-0 py-0 shadow-none">
          {actions.items.map((a) => {
              const status = STATUS[a.status] ?? { label: a.status, tone: "neutral" as Tone }
              const args = Object.entries(a.args)
                .map(([k, v]) => `${k.replaceAll("_", " ")}: ${v}`)
                .join(" · ")
              return (
                <div key={a.id} className="flex flex-col gap-3 px-5 py-4 sm:flex-row sm:items-center">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[15px] font-medium">{toolLabel(a.tool)}</span>
                      <ToneBadge tone={status.tone}>{status.label}</ToneBadge>
                      <ToneBadge tone={tierOf(a.tier).tone}>{tierOf(a.tier).label}</ToneBadge>
                    </div>
                    <div className="mt-1 text-[13px] text-muted-foreground">
                      <Link href={`/alerts/${encodeURIComponent(a.alert_id)}`} className="hover:text-foreground">
                        alert {a.alert_id}
                      </Link>
                      {args && ` · ${args}`} · {VIA[a.via] ?? sentence(a.via)} · {ago(a.ts)}
                    </div>
                    {a.reverted_by && (
                      <div className="mt-1 text-[13px] text-muted-foreground">
                        Undone by {a.reverted_by}
                        {a.revert_reason ? `: ${a.revert_reason}` : ""}
                      </div>
                    )}
                  </div>
                  {a.status === "executed" && a.undo_tool && (
                    <Button variant="outline" size="sm" onClick={() => setUndoing(a)}>
                      <Undo2 /> Undo
                    </Button>
                  )}
                </div>
              )
            })}
        </Card>
      )}
      <LoadMore hasMore={actions.hasMore} loading={actions.loadingMore} onClick={actions.loadMore} />
      <ReasonDialog
        path={undoing ? `/v1/actions/${undoing.id}/revert` : null}
        title="Undo this action?"
        description={undoing ? `${toolLabel(undoing.tool)} on alert ${undoing.alert_id} will be reversed with “${toolLabel(undoing.undo_tool)}”.` : ""}
        confirm="Undo"
        done="Undone."
        placeholder="Why are you undoing it?"
        onClose={() => setUndoing(null)}
        onDone={() => {
          setUndoing(null)
          actions.mutate()
        }}
      />
    </>
  )
}
