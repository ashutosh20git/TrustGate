"use client"

import { useState } from "react"
import { Download } from "lucide-react"

import { LoadError, Loading, PageHeader, ToneBadge } from "@/components/tg/bits"
import { ReasonDialog } from "@/components/tg/reason-dialog"
import { Button } from "@/components/ui/button"
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { useTg } from "@/lib/api"
import type { Tone } from "@/lib/format"
import type { Compliance, Pin } from "@/lib/types"

const FRAMEWORKS = { "cert-in": "CERT-In", dpdp: "DPDP", iso27001: "ISO 27001", "nist-800-53": "NIST 800-53" }
const STATUS: Record<string, { label: string; tone: Tone }> = {
  met: { label: "Met", tone: "success" },
  confirm: { label: "Needs a human to confirm", tone: "warning" },
  gap: { label: "Gap", tone: "danger" },
}
const PIN: Record<string, { label: string; tone: Tone }> = {
  pinned: { label: "Approved", tone: "success" },
  disabled: { label: "Switched off", tone: "danger" },
  quarantined: { label: "Quarantined", tone: "warning" },
}

export default function CompliancePage() {
  const [framework, setFramework] = useState<keyof typeof FRAMEWORKS>("cert-in")
  const report = useTg<Compliance>(`/v1/compliance/${framework}`)
  const pins = useTg<Pin[]>("/v1/mcp/pins")
  const [repinning, setRepinning] = useState<Pin | null>(null)

  function download() {
    if (!report.data) return
    const blob = new Blob([JSON.stringify(report.data, null, 2)], { type: "application/json" })
    const link = document.createElement("a")
    link.href = URL.createObjectURL(blob)
    link.download = `trustgate-${framework}.json`
    link.click()
    URL.revokeObjectURL(link.href)
  }

  return (
    <>
      <PageHeader title="Compliance & tools" description="Evidence for audits, and the MCP tools the AI agent is allowed to use." />
      <div className="flex flex-col gap-6">
        <Card className="shadow-none">
          <CardHeader>
            <CardTitle className="text-lg">Compliance evidence</CardTitle>
            <CardDescription>{report.data?.disclaimer ?? "Evidence collected by TrustGate to support a compliance review."}</CardDescription>
            <CardAction>
              <Button variant="outline" size="sm" onClick={download} disabled={!report.data}>
                <Download /> Evidence pack
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <ToggleGroup
              type="single"
              variant="outline"
              value={framework}
              onValueChange={(v) => v && setFramework(v as keyof typeof FRAMEWORKS)}
              className="flex-wrap"
            >
              {Object.entries(FRAMEWORKS).map(([k, label]) => (
                <ToggleGroupItem key={k} value={k} className="px-3 text-[13px]">
                  {label}
                </ToggleGroupItem>
              ))}
            </ToggleGroup>
            {report.error ? (
              <LoadError error={report.error} />
            ) : !report.data ? (
              <Loading rows={2} />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="w-40">Control</TableHead>
                    <TableHead>Requirement and evidence</TableHead>
                    <TableHead className="w-52">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {report.data.controls.map((c) => (
                    <TableRow key={c.id} className="align-top">
                      <TableCell className="font-medium whitespace-normal">{c.id}</TableCell>
                      <TableCell className="whitespace-normal">
                        <div>{c.requirement}</div>
                        <div className="mt-1 text-[13px] text-muted-foreground">{c.evidence}</div>
                      </TableCell>
                      <TableCell>
                        <ToneBadge tone={(STATUS[c.status] ?? STATUS.confirm).tone}>{(STATUS[c.status] ?? { label: c.status }).label}</ToneBadge>
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
            <CardTitle className="text-lg">MCP tools</CardTitle>
            <CardDescription>
              Each tool&apos;s description is fingerprinted when first seen. A tool that changes is switched off until an analyst approves it again.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {pins.error ? (
              <LoadError error={pins.error} />
            ) : !pins.data ? (
              <Loading rows={1} />
            ) : pins.data.length === 0 ? (
              <p className="text-sm text-muted-foreground">No MCP tools connected yet.</p>
            ) : (
              <ul className="flex flex-col divide-y">
                {pins.data.map((p) => {
                  const state = PIN[p.status] ?? { label: p.status, tone: "neutral" as Tone }
                  return (
                    <li key={`${p.server}/${p.name}`} className="flex items-center gap-3 py-3">
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="font-medium">
                            {p.server}/{p.name}
                          </span>
                          <ToneBadge tone={state.tone}>{state.label}</ToneBadge>
                        </div>
                        {p.reasons.length > 0 && <div className="mt-0.5 text-[13px] text-muted-foreground">{p.reasons.join("; ")}</div>}
                      </div>
                      {p.status !== "pinned" && (
                        <Button variant="outline" size="sm" onClick={() => setRepinning(p)}>
                          Approve again
                        </Button>
                      )}
                    </li>
                  )
                })}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>
      <ReasonDialog
        path={repinning ? `/v1/mcp/pins/${encodeURIComponent(repinning.server)}/${encodeURIComponent(repinning.name)}/approve` : null}
        title="Approve this MCP tool again?"
        description={repinning ? `${repinning.server}/${repinning.name} will be usable by the AI agent again with its current description.` : ""}
        confirm="Approve"
        done="Tool approved."
        placeholder="Why is the change safe?"
        onClose={() => setRepinning(null)}
        onDone={() => {
          setRepinning(null)
          pins.mutate()
        }}
      />
    </>
  )
}
