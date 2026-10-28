import type * as React from "react"
import { AlertCircle, Loader2 } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { Skeleton } from "@/components/ui/skeleton"
import { cn } from "@/lib/utils"
import type { Tone } from "@/lib/format"

const TONE_TEXT: Record<Tone, string> = {
  success: "text-success bg-success/10",
  warning: "text-warning bg-warning/12",
  danger: "text-danger bg-danger/10",
  info: "text-info bg-info/10",
  violet: "text-violet bg-violet/10",
  neutral: "text-muted-foreground bg-muted",
}
const TONE_DOT: Record<Tone, string> = {
  success: "bg-success",
  warning: "bg-warning",
  danger: "bg-danger",
  info: "bg-info",
  violet: "bg-violet",
  neutral: "bg-neutral",
}

export function ToneBadge({ tone, children, className }: { tone: Tone; children: React.ReactNode; className?: string }) {
  return (
    <Badge variant="ghost" className={cn("h-6 rounded-full px-2.5 font-medium", TONE_TEXT[tone], className)}>
      {children}
    </Badge>
  )
}

export function Dot({ tone, className }: { tone: Tone; className?: string }) {
  return <span aria-hidden className={cn("inline-block size-2 shrink-0 rounded-full", TONE_DOT[tone], className)} />
}

export function PageHeader({ title, description, children }: { title: string; description: string; children?: React.ReactNode }) {
  return (
    <div className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">{title}</h1>
        <p className="mt-1.5 max-w-2xl text-[15px] text-muted-foreground">{description}</p>
      </div>
      {children}
    </div>
  )
}

export function Stat({
  label,
  value,
  hint,
  highlight,
  small,
}: {
  label: string
  value: React.ReactNode
  hint?: string
  highlight?: boolean
  small?: boolean
}) {
  return (
    <Card className={cn("gap-0 py-0 shadow-none", highlight && "ring-2 ring-primary")}>
      <CardContent className={cn("px-5", small ? "py-4" : "py-5")}>
        <div className="text-[13px] font-medium text-muted-foreground">{label}</div>
        <div className={cn("mt-1 font-semibold tracking-tight tabular-nums", small ? "text-xl" : "text-[32px] leading-10")}>
          {value}
        </div>
        {hint && <div className="mt-1 text-xs text-muted-foreground">{hint}</div>}
      </CardContent>
    </Card>
  )
}

export function EmptyState({ icon, title, description }: { icon: React.ReactNode; title: string; description: string }) {
  return (
    <Empty className="py-14">
      <EmptyHeader>
        <EmptyMedia variant="icon">{icon}</EmptyMedia>
        <EmptyTitle>{title}</EmptyTitle>
        <EmptyDescription>{description}</EmptyDescription>
      </EmptyHeader>
    </Empty>
  )
}

export function LoadError({ error }: { error: Error }) {
  return (
    <div className="flex items-center gap-2 rounded-xl border border-danger/30 bg-danger/5 px-4 py-3 text-sm text-danger">
      <AlertCircle className="size-4" />
      {error.message || "Could not load this view."}
    </div>
  )
}

export function Loading({ rows = 3 }: { rows?: number }) {
  return (
    <div className="flex flex-col gap-3">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-20 w-full rounded-xl" />
      ))}
    </div>
  )
}

/** The foot of a paged list: a button for the next page, or nothing once it's all shown. */
export function LoadMore({ hasMore, loading, onClick }: { hasMore: boolean; loading: boolean; onClick: () => void }) {
  if (!hasMore) return null
  return (
    <div className="mt-4 flex justify-center">
      <Button variant="outline" onClick={onClick} disabled={loading}>
        {loading && <Loader2 className="animate-spin" />}
        Load more
      </Button>
    </div>
  )
}

/** Untrusted text from an alert: always plain text, never markup or links. */
export function Quarantined({ children }: { children: string }) {
  return (
    <pre className="max-h-64 overflow-auto rounded-lg border bg-muted/50 px-3.5 py-2.5 font-mono text-[12.5px] leading-relaxed whitespace-pre-wrap break-words text-foreground/90">
      {children || "(empty)"}
    </pre>
  )
}
