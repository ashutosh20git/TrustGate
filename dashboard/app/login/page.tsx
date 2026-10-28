"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { Loader2, ShieldCheck } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

export default function LoginPage() {
  const [token, setToken] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const router = useRouter()

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const res = await fetch("/api/session", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-tg-request": "1" },
        body: JSON.stringify({ token }),
      })
      if (res.ok) {
        router.replace("/")
        return
      }
      setError((await res.json().catch(() => ({}))).error ?? "Sign-in failed.")
    } catch {
      setError("TrustGate is not reachable.")
    }
    setBusy(false)
  }

  return (
    <main className="flex min-h-svh items-center justify-center bg-background px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center text-center">
          <div className="mb-4 flex size-14 items-center justify-center rounded-2xl bg-primary text-primary-foreground shadow-sm">
            <ShieldCheck className="size-7" />
          </div>
          <h1 className="text-2xl font-semibold tracking-tight">Sign in to TrustGate</h1>
          <p className="mt-1.5 text-[15px] text-muted-foreground">Review what the AI agent did and what needs you.</p>
        </div>
        <Card className="shadow-sm">
          <CardContent>
            <form onSubmit={submit} className="flex flex-col gap-4">
              <div className="flex flex-col gap-2">
                <Label htmlFor="token">Analyst token</Label>
                <Input
                  id="token"
                  type="password"
                  autoComplete="off"
                  autoFocus
                  placeholder="Paste your token"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  aria-invalid={!!error}
                  className="h-10"
                />
                {error && <p className="text-sm text-danger">{error}</p>}
              </div>
              <Button type="submit" size="lg" className="h-10" disabled={busy || !token.trim()}>
                {busy && <Loader2 className="animate-spin" />}
                Enter
              </Button>
            </form>
          </CardContent>
        </Card>
        <p className="mt-5 px-2 text-center text-xs leading-relaxed text-muted-foreground">
          Use the token <code className="font-mono">scripts/init_secrets.py</code> printed when your analyst was created.
          The values in <code className="font-mono">secrets/analyst_tokens.txt</code> are hashes, not tokens.
        </p>
      </div>
    </main>
  )
}
