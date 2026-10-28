"use client"

import Link from "next/link"
import { ChevronRight } from "lucide-react"

import { Dot } from "@/components/tg/bits"
import { clock, describe, plainReason } from "@/lib/format"
import type { AuditRecord } from "@/lib/types"

/** A vertical list of audit events, each a plain sentence with its time and reasons. */
export function EventList({ records, showAlert, compact }: { records: AuditRecord[]; showAlert?: boolean; compact?: boolean }) {
  return (
    <ol className="relative">
      {records.map((rec, i) => {
        const { text, tone } = describe(rec)
        return (
          <li key={rec.id} className="relative flex gap-3.5 pb-5 last:pb-0">
            {i < records.length - 1 && <span aria-hidden className="absolute top-4 left-[3.5px] h-full w-px bg-border" />}
            <Dot tone={tone} className="relative mt-1.5" />
            <div className="min-w-0 flex-1">
              <div className="text-[14.5px] leading-snug">{text}</div>
              <div className="mt-0.5 flex flex-wrap items-center gap-x-2 text-xs text-muted-foreground">
                <span>{clock(rec.ts)}</span>
                {showAlert && rec.alert_id && (
                  <Link href={`/alerts/${encodeURIComponent(rec.alert_id)}`} className="inline-flex items-center hover:text-foreground">
                    alert {rec.alert_id}
                    <ChevronRight className="size-3" />
                  </Link>
                )}
              </div>
              {!compact && rec.reasons.length > 0 && rec.decision !== "allow" && (
                <ul className="mt-2 flex flex-col gap-1 rounded-lg bg-muted/60 px-3 py-2 text-[13px] text-muted-foreground">
                  {rec.reasons.map((r) => (
                    <li key={r} title={r}>
                      {plainReason(r)}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </li>
        )
      })}
    </ol>
  )
}
