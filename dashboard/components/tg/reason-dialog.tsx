"use client"

import { useState } from "react"
import { Loader2 } from "lucide-react"
import { toast } from "sonner"

import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { send } from "@/lib/api"

/** A confirmation that needs a written reason, then POSTs {reason} to `path`. */
export function ReasonDialog({
  path,
  title,
  description,
  confirm,
  done,
  placeholder,
  onClose,
  onDone,
}: {
  path: string | null
  title: string
  description: string
  confirm: string
  done: string
  placeholder: string
  onClose: () => void
  onDone: () => void
}) {
  const [reason, setReason] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function close() {
    setReason("")
    setError(null)
    setBusy(false)
    onClose()
  }

  async function submit() {
    if (!path) return
    setBusy(true)
    setError(null)
    const err = await send(path, { reason })
    if (err) {
      setError(err)
      setBusy(false)
      return
    }
    toast.success(done)
    setReason("")
    setBusy(false)
    onDone()
  }

  return (
    <Dialog open={!!path} onOpenChange={(open) => !open && close()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-2">
          <Label htmlFor="dialog-reason">Reason</Label>
          <Textarea id="dialog-reason" placeholder={placeholder} value={reason} onChange={(e) => setReason(e.target.value)} />
          {error && <p className="rounded-lg bg-danger/8 px-3 py-2 text-sm text-danger">{error}</p>}
        </div>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <Button disabled={busy || !reason.trim()} onClick={submit}>
            {busy && <Loader2 className="animate-spin" />}
            {confirm}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
