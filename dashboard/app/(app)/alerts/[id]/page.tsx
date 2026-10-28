import { Suspense } from "react"

import { Loading } from "@/components/tg/bits"
import { AlertView } from "./alert-view"

export default function AlertPage() {
  return (
    <Suspense fallback={<Loading rows={3} />}>
      <AlertView />
    </Suspense>
  )
}
