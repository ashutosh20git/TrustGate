import { cookies } from "next/headers"
import { NextResponse } from "next/server"

import { allowed, callProxy, sameOrigin, SESSION_COOKIE } from "@/lib/server/trustgate"

type Context = { params: Promise<{ path: string[] }> }

async function forward(request: Request, { params }: Context, method: "GET" | "POST") {
  const path = (await params).path.map(encodeURIComponent).join("/")
  if (!allowed(method, path)) return NextResponse.json({ detail: "Not available." }, { status: 404 })
  if (method === "POST" && !sameOrigin(request)) return NextResponse.json({ detail: "Bad request." }, { status: 400 })
  const store = await cookies()
  const token = store.get(SESSION_COOKIE)?.value
  if (!token) return NextResponse.json({ detail: "Signed out." }, { status: 401 })

  const headers: Record<string, string> = {}
  const second = request.headers.get("x-second-analyst-token")
  if (second) headers["X-Second-Analyst-Token"] = second
  if (method === "POST") headers["Content-Type"] = "application/json"
  let upstream: Response
  try {
    upstream = await callProxy(path + new URL(request.url).search, {
      method,
      token,
      headers,
      body: method === "POST" ? await request.text() : undefined,
    })
  } catch {
    return NextResponse.json({ detail: "TrustGate is not reachable." }, { status: 502 })
  }
  if (upstream.status === 401 && !second) store.delete(SESSION_COOKIE)
  const out = new Headers({ "Content-Type": upstream.headers.get("content-type") ?? "application/json", "Cache-Control": "no-store" })
  // Paging: the cursor for the next page and, for the queue, its size.
  for (const name of ["x-next-cursor", "x-total-count"]) {
    const value = upstream.headers.get(name)
    if (value) out.set(name, value)
  }
  return new NextResponse(upstream.body, { status: upstream.status, headers: out })
}

export function GET(request: Request, context: Context) {
  return forward(request, context, "GET")
}

export function POST(request: Request, context: Context) {
  return forward(request, context, "POST")
}
