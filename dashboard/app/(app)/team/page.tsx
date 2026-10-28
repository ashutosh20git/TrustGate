"use client"

import { useState, type FormEvent } from "react"
import { Check, Copy, KeyRound, Loader2, Lock, UserMinus, UserPlus, Users } from "lucide-react"
import { toast } from "sonner"

import { EmptyState, LoadError, Loading, PageHeader, ToneBadge } from "@/components/tg/bits"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useTg } from "@/lib/api"
import { ago } from "@/lib/format"
import type { Me, Role, TeamMember } from "@/lib/types"

type Issued = { member: TeamMember; token: string }
type Pending = { member: TeamMember; kind: "token" | "remove" }

const ROLE_TEXT: Record<Role, string> = {
  analyst: "Reviews alerts, approves, rejects and undoes actions",
  admin: "Everything an analyst does, and manages the team",
}

/** POST to the team API and read the JSON back (the token comes only in this response). */
async function post<T>(path: string, body?: unknown): Promise<{ data?: T; error?: string }> {
  try {
    const res = await fetch(`/api/tg${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-tg-request": "1" },
      body: JSON.stringify(body ?? {}),
    })
    const json = await res.json().catch(() => ({}))
    return res.ok ? { data: json as T } : { error: String(json.detail ?? res.statusText) }
  } catch {
    return { error: "TrustGate is not reachable." }
  }
}

export default function TeamPage() {
  const me = useTg<Me>("/v1/me", { refreshInterval: 60_000 })
  const team = useTg<TeamMember[]>(me.data?.role === "admin" ? "/v1/team" : null)
  const [adding, setAdding] = useState(false)
  const [pending, setPending] = useState<Pending | null>(null)
  const [issued, setIssued] = useState<Issued | null>(null)

  if (me.data && me.data.role !== "admin") {
    return (
      <>
        <PageHeader title="Team" description="Who can sign in to TrustGate." />
        <Card className="shadow-none">
          <EmptyState icon={<Lock />} title="Admins only" description="Ask an admin to add, remove or reset someone's access." />
        </Card>
      </>
    )
  }

  const active = team.data?.filter((m) => m.active) ?? []
  const removed = team.data?.filter((m) => !m.active) ?? []

  return (
    <>
      <PageHeader title="Team" description="Add the people who review the AI agent's actions. Each person gets their own token to sign in with.">
        <Button onClick={() => setAdding(true)} disabled={!team.data}>
          <UserPlus /> Add member
        </Button>
      </PageHeader>

      {team.error || me.error ? (
        <LoadError error={(team.error ?? me.error) as Error} />
      ) : !team.data ? (
        <Loading rows={3} />
      ) : (
        <div className="flex flex-col gap-8">
          <section>
            <h2 className="mb-3 text-[13px] font-medium text-muted-foreground">Active · {active.length}</h2>
            {active.length < 2 && (
              <p className="mb-3 rounded-xl bg-warning/10 px-4 py-3 text-sm text-warning">
                Disruptive actions need two different people to approve them. Add at least one more member.
              </p>
            )}
            <Card className="divide-y gap-0 py-0 shadow-none">
              {active.map((m) => (
                <MemberRow key={m.name} member={m} me={me.data} onAction={(kind) => setPending({ member: m, kind })} />
              ))}
            </Card>
          </section>
          {removed.length > 0 && (
            <section>
              <h2 className="mb-3 text-[13px] font-medium text-muted-foreground">Removed · {removed.length}</h2>
              <Card className="divide-y gap-0 py-0 shadow-none">
                {removed.map((m) => (
                  <MemberRow key={m.name} member={m} me={me.data} onAction={() => {}} />
                ))}
              </Card>
            </section>
          )}
        </div>
      )}

      <AddDialog
        open={adding}
        onClose={() => setAdding(false)}
        onIssued={(i) => {
          setAdding(false)
          setIssued(i)
          team.mutate()
        }}
      />
      <ConfirmDialog
        pending={pending}
        onClose={() => setPending(null)}
        onDone={(i) => {
          setPending(null)
          if (i) setIssued(i)
          team.mutate()
        }}
      />
      <TokenDialog issued={issued} onClose={() => setIssued(null)} />
    </>
  )
}

function MemberRow({ member: m, me, onAction }: { member: TeamMember; me?: Me; onAction: (kind: Pending["kind"]) => void }) {
  const self = m.name === me?.name
  const detail = !m.active
    ? `Removed by ${m.removed_by ?? "an admin"} ${ago(m.removed_at)}`
    : m.source === "setup"
      ? "Set up at install · change in the secrets file"
      : `Added by ${m.added_by} ${ago(m.added_at)}${m.token_reset_at ? ` · token reset ${ago(m.token_reset_at)}` : ""}`
  return (
    <div className="flex flex-col gap-3 px-5 py-4 sm:flex-row sm:items-center">
      <div className="flex min-w-0 flex-1 items-center gap-3">
        <div className="flex size-9 shrink-0 items-center justify-center rounded-full bg-muted text-sm font-semibold uppercase text-muted-foreground">
          {m.name.slice(0, 2)}
        </div>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="truncate text-[15px] font-medium">{m.name}</span>
            {self && <span className="text-[13px] text-muted-foreground">(you)</span>}
            <ToneBadge tone={m.role === "admin" ? "violet" : "neutral"}>{m.role === "admin" ? "Admin" : "Analyst"}</ToneBadge>
          </div>
          <div className="mt-0.5 text-[13px] text-muted-foreground">{detail}</div>
        </div>
      </div>
      {m.active && m.source === "team" && !self && (
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => onAction("token")}>
            <KeyRound /> New token
          </Button>
          <Button variant="outline" size="sm" className="text-danger hover:text-danger" onClick={() => onAction("remove")}>
            <UserMinus /> Remove
          </Button>
        </div>
      )}
    </div>
  )
}

function AddDialog({ open, onClose, onIssued }: { open: boolean; onClose: () => void; onIssued: (i: Issued) => void }) {
  const [name, setName] = useState("")
  const [role, setRole] = useState<Role>("analyst")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function reset() {
    setName("")
    setRole("analyst")
    setError(null)
    setBusy(false)
  }

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    const { data, error: err } = await post<Issued>("/v1/team", { name: name.trim(), role })
    if (err || !data) {
      setError(err ?? "Could not add this member.")
      setBusy(false)
      return
    }
    reset()
    onIssued(data)
  }

  return (
    <Dialog open={open} onOpenChange={(o) => {
        if (!o) {
          reset()
          onClose()
        }
      }}>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={submit} className="flex flex-col gap-4">
          <DialogHeader>
            <DialogTitle>Add a team member</DialogTitle>
            <DialogDescription>You&apos;ll get a token to hand to them. It&apos;s shown once.</DialogDescription>
          </DialogHeader>
          <div className="flex flex-col gap-2">
            <Label htmlFor="member-name">Name</Label>
            <Input
              id="member-name"
              placeholder="e.g. priya or priya@corp.example"
              autoComplete="off"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">Letters, digits and . _ @ - only. This name appears in the activity log.</p>
          </div>
          <div className="flex flex-col gap-2">
            <Label>Role</Label>
            <Select value={role} onValueChange={(v) => setRole(v as Role)}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="analyst">Analyst</SelectItem>
                <SelectItem value="admin">Admin</SelectItem>
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">{ROLE_TEXT[role]}</p>
          </div>
          {error && <p className="rounded-lg bg-danger/8 px-3 py-2 text-sm text-danger">{error}</p>}
          <DialogFooter>
            <DialogClose asChild>
              <Button type="button" variant="outline">Cancel</Button>
            </DialogClose>
            <Button type="submit" disabled={busy || !name.trim()}>
              {busy && <Loader2 className="animate-spin" />}
              Add member
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function ConfirmDialog({ pending, onClose, onDone }: { pending: Pending | null; onClose: () => void; onDone: (i?: Issued) => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const name = pending?.member.name ?? ""
  const remove = pending?.kind === "remove"

  async function submit() {
    if (!pending) return
    setBusy(true)
    setError(null)
    const path = `/v1/team/${encodeURIComponent(name)}/${remove ? "remove" : "token"}`
    const { data, error: err } = await post<Issued | TeamMember>(path)
    setBusy(false)
    if (err) {
      setError(err)
      return
    }
    if (remove) {
      toast.success(`${name} can no longer sign in.`)
      onDone()
    } else {
      onDone(data as Issued)
    }
  }

  return (
    <Dialog open={!!pending} onOpenChange={(o) => {
        if (!o) {
          setError(null)
          onClose()
        }
      }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{remove ? `Remove ${name}?` : `Give ${name} a new token?`}</DialogTitle>
          <DialogDescription>
            {remove
              ? "Their token stops working right away and they're signed out. Their past decisions stay in the activity log."
              : "Their current token stops working right away. Use this if they lost it or it may have leaked."}
          </DialogDescription>
        </DialogHeader>
        {error && <p className="rounded-lg bg-danger/8 px-3 py-2 text-sm text-danger">{error}</p>}
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <Button variant={remove ? "destructive" : "default"} disabled={busy} onClick={submit}>
            {busy && <Loader2 className="animate-spin" />}
            {remove ? "Remove" : "Make new token"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function TokenDialog({ issued, onClose }: { issued: Issued | null; onClose: () => void }) {
  const [copied, setCopied] = useState(false)

  async function copy() {
    if (!issued) return
    try {
      await navigator.clipboard.writeText(issued.token)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      toast.error("Couldn't copy. Select the token and copy it by hand.")
    }
  }

  return (
    <Dialog open={!!issued} onOpenChange={(o) => {
        if (!o) {
          setCopied(false)
          onClose()
        }
      }}>
      <DialogContent className="sm:max-w-md" onInteractOutside={(e) => e.preventDefault()}>
        <DialogHeader>
          <DialogTitle>Token for {issued?.member.name}</DialogTitle>
          <DialogDescription>
            Copy it now and send it to them privately. You won&apos;t be able to see it again. Never give it to the AI agent.
          </DialogDescription>
        </DialogHeader>
        <div className="flex items-center gap-2">
          <code className="min-w-0 flex-1 rounded-lg border bg-muted/50 px-3 py-2.5 font-mono text-[13px] break-all select-all">
            {issued?.token}
          </code>
          <Button variant="outline" size="icon" onClick={copy} aria-label="Copy token">
            {copied ? <Check /> : <Copy />}
          </Button>
        </div>
        <p className="text-[13px] text-muted-foreground">
          They sign in at this dashboard&apos;s address by pasting the token. {issued?.member.role === "admin" ? "As an admin" : "As an analyst"}, they{" "}
          {issued?.member.role === "admin" ? "can also manage the team" : "can review and decide on held actions"}.
        </p>
        <DialogFooter>
          <Button onClick={onClose}>
            <Users /> Done
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
