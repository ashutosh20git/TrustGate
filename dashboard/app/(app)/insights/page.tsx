"use client"

import { LoadError, Loading, PageHeader, ToneBadge } from "@/components/tg/bits"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useTg } from "@/lib/api"
import { factValue, plainReason, sentence, tierOf, toolLabel } from "@/lib/format"
import type { AnalystScores, Rollout } from "@/lib/types"

export default function InsightsPage() {
  const rollout = useTg<Rollout>("/v1/rollout")
  const analysts = useTg<AnalystScores>("/v1/analysts")

  return (
    <>
      <PageHeader title="Insights" description="Whether the gate is ready to enforce, and whether human review is still a real check." />
      <div className="flex flex-col gap-6">
        <Card className="shadow-none">
          <CardHeader>
            <CardTitle className="text-lg">Ready to enforce?</CardTitle>
            <CardDescription>
              In monitor mode TrustGate only records what it would have held. {rollout.data && sentence(rollout.data.criteria)}.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {rollout.error ? (
              <LoadError error={rollout.error} />
            ) : !rollout.data ? (
              <Loading rows={1} />
            ) : rollout.data.tools.length === 0 ? (
              <p className="text-sm text-muted-foreground">No monitor-mode decisions yet. This fills in while TRUSTGATE_MODE=monitor.</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead>Action</TableHead>
                    <TableHead className="text-right">Decisions</TableHead>
                    <TableHead className="text-right">Would hold</TableHead>
                    <TableHead className="text-right">Failed safe</TableHead>
                    <TableHead>Main reasons</TableHead>
                    <TableHead>Ready</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rollout.data.tools.map((t) => (
                    <TableRow key={t.tool}>
                      <TableCell>
                        <div className="font-medium">{toolLabel(t.tool)}</div>
                        <div className="text-xs text-muted-foreground">{tierOf(t.tier).label}</div>
                      </TableCell>
                      <TableCell className="text-right tabular-nums">{t.decisions}</TableCell>
                      <TableCell className="text-right tabular-nums">{Math.round(t.would_block_rate * 100)}%</TableCell>
                      <TableCell className="text-right tabular-nums">{t.fail_closed}</TableCell>
                      <TableCell className="max-w-xs text-[13px] whitespace-normal text-muted-foreground">
                        {t.top_reasons.map(plainReason).join("; ") || "—"}
                      </TableCell>
                      <TableCell>
                        <ToneBadge tone={t.ready_to_enforce ? "success" : "neutral"}>{t.ready_to_enforce ? "Ready" : "Not yet"}</ToneBadge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        <Card className="shadow-none">
          <CardHeader>
            <CardTitle className="text-lg">Analysts</CardTitle>
            <CardDescription>
              Spots rubber-stamping, including practice cases mixed into the queue. {analysts.data && sentence(analysts.data.criteria)}.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {analysts.error ? (
              <LoadError error={analysts.error} />
            ) : !analysts.data ? (
              <Loading rows={1} />
            ) : analysts.data.analysts.length === 0 ? (
              <p className="text-sm text-muted-foreground">No analyst decisions yet.</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    {Object.keys(analysts.data.analysts[0]).map((k) => (
                      <TableHead key={k}>{sentence(k.replaceAll("_", " "))}</TableHead>
                    ))}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {analysts.data.analysts.map((row, i) => (
                    <TableRow key={i}>
                      {Object.entries(row).map(([k, v]) => (
                        <TableCell key={k} className="whitespace-normal tabular-nums">
                          {v == null ? "—" : factValue(v)}
                        </TableCell>
                      ))}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>
    </>
  )
}
