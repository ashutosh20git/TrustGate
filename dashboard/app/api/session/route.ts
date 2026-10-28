import { cookies } from "next/headers"
import { NextResponse } from "next/server"

import { callProxy, cookieOptions, sameOrigin, SESSION_COOKIE } from "@/lib/server/trustgate"

// Sign in: check the analyst token against the proxy, then keep it in an httpOnly cookie
// so page scripts never see it.
export async function POST(request: Request) {
  if (!sameOrigin(request)) return NextResponse.json({ error: "Bad request." }, { status: 400 })
  const body = (await request.json().catch(() => ({}))) as { token?: unknown }
  const token = typeof body.token === "string" ? body.token.trim() : ""
  if (!token) return NextResponse.json({ error: "Paste your analyst token." }, { status: 400 })
  let check: Response
  try {
    check = await callProxy("v1/metrics", { token })
  } catch {
    return NextResponse.json({ error: "TrustGate is not reachable. Is the proxy running?" }, { status: 502 })
  }
  if (check.status === 503) {
    return NextResponse.json(
      { error: "Analyst sign-in is not set up yet. Run scripts/init_secrets.py --analyst <name>." },
      { status: 503 },
    )
  }
  if (!check.ok) {
    return NextResponse.json(
      {
        error:
          token.length === 64 && /^[0-9a-f]+$/.test(token)
            ? "That looks like the hash from secrets/analyst_tokens.txt. Use the token init_secrets.py printed."
            : "That token was not accepted.",
      },
      { status: 401 },
    )
  }
  ;(await cookies()).set(SESSION_COOKIE, token, cookieOptions(request))
  return NextResponse.json({ ok: true })
}

export async function DELETE(request: Request) {
  if (!sameOrigin(request)) return NextResponse.json({ error: "Bad request." }, { status: 400 })
  ;(await cookies()).delete(SESSION_COOKIE)
  return NextResponse.json({ ok: true })
}
