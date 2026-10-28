import "server-only"

// The TrustGate proxy, reachable only from this server (never from the browser).
export const PROXY_URL = (process.env.TRUSTGATE_PROXY_URL ?? "http://127.0.0.1:8080").replace(/\/+$/, "")
export const SESSION_COOKIE = "tg_session"

// The analyst views this dashboard may read and the decisions it may send. Agent tool calls
// (/v1/tools/...) are deliberately absent: the dashboard can never act as the agent.
const READS = [
  /^v1\/metrics$/,
  /^v1\/rollout$/,
  /^v1\/analysts$/,
  /^v1\/mcp\/pins$/,
  /^v1\/actions$/,
  /^v1\/audit$/,
  /^v1\/alerts$/,
  /^v1\/alert-counts$/,
  /^v1\/alerts\/[^/]+$/,
  /^v1\/escalations$/,
  /^v1\/escalations\/[^/]+\/explain$/,
  /^v1\/compliance\/[a-z0-9-]+$/,
  /^v1\/me$/,
  /^v1\/team$/,
]
const WRITES = [
  /^v1\/escalations\/[^/]+\/(approve|reject)$/,
  /^v1\/actions\/[^/]+\/revert$/,
  /^v1\/mcp\/pins\/[^/]+\/[^/]+\/approve$/,
  /^v1\/team$/,
  /^v1\/team\/[^/]+\/(token|remove)$/,
]

export function allowed(method: "GET" | "POST", path: string): boolean {
  return (method === "GET" ? READS : WRITES).some((re) => re.test(path))
}

export async function callProxy(path: string, init: RequestInit & { token: string }): Promise<Response> {
  const { token, headers, ...rest } = init
  return fetch(`${PROXY_URL}/${path}`, {
    ...rest,
    cache: "no-store",
    headers: { ...headers, Authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(15_000),
  })
}

export function cookieOptions(request: Request) {
  const https = new URL(request.url).protocol === "https:" || request.headers.get("x-forwarded-proto") === "https"
  return { httpOnly: true, sameSite: "strict" as const, secure: https, path: "/", maxAge: 60 * 60 * 12 }
}

// Writes need a header a cross-site form cannot send, on top of the SameSite=Strict cookie.
export function sameOrigin(request: Request): boolean {
  if (request.headers.get("x-tg-request") !== "1") return false
  const origin = request.headers.get("origin")
  return !origin || new URL(origin).host === request.headers.get("host")
}
