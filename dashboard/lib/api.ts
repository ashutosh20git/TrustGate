"use client"

import useSWR, { type SWRConfiguration } from "swr"
import useSWRInfinite from "swr/infinite"

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
  }
}

async function detail(res: Response): Promise<string> {
  try {
    const body = await res.json()
    return String(body.detail ?? body.error ?? res.statusText)
  } catch {
    return res.statusText
  }
}

async function load(url: string): Promise<Response> {
  const res = await fetch(url, { cache: "no-store" })
  if (res.status === 401) {
    // A full load, not a client navigation: nothing cached from the old session survives.
    // eslint-disable-next-line @next/next/no-location-assign-relative-destination
    window.location.assign("/login")
    throw new ApiError(401, "Signed out")
  }
  if (!res.ok) throw new ApiError(res.status, await detail(res))
  return res
}

async function fetcher<T>(url: string): Promise<T> {
  return (await load(url)).json()
}

type Page<T> = { items: T[]; next: string | null; total: number | null }

async function pageFetcher<T>(url: string): Promise<Page<T>> {
  const res = await load(url)
  const total = res.headers.get("x-total-count")
  return { items: await res.json(), next: res.headers.get("x-next-cursor"), total: total === null ? null : Number(total) }
}

function withCursor(path: string, cursor: string | null): string {
  return cursor ? `${path}${path.includes("?") ? "&" : "?"}cursor=${encodeURIComponent(cursor)}` : path
}

/** Read an analyst view from the proxy (path like "/v1/metrics"); refreshes every 10 seconds. */
export function useTg<T>(path: string | null, config?: SWRConfiguration<T>) {
  return useSWR<T>(path ? `/api/tg${path}` : null, fetcher, { refreshInterval: 10_000, ...config })
}

/**
 * Read a cursor-paged list (path like "/v1/alerts?limit=50"). Pages load on demand with
 * loadMore(); every loaded page refreshes every 10 seconds. Each page starts after the
 * previous page's last row, so rows arriving meanwhile never repeat or go missing.
 */
export function usePaged<T>(path: string | null) {
  const { data, error, size, setSize, isValidating, mutate } = useSWRInfinite<Page<T>>(
    (index, previous: Page<T> | null) => {
      if (!path) return null
      if (index === 0) return `/api/tg${path}`
      return previous?.next ? `/api/tg${withCursor(path, previous.next)}` : null
    },
    pageFetcher,
    { refreshInterval: 10_000, revalidateAll: true },
  )
  const last = data?.[data.length - 1]
  return {
    items: data ? data.flatMap((p) => p.items) : undefined,
    total: data?.[0]?.total ?? null,
    error: error as Error | undefined,
    hasMore: !!last?.next,
    loadingMore: isValidating && size > (data?.length ?? 0),
    loadMore: () => setSize(size + 1),
    mutate,
  }
}

/** Every page of a list, one request after another (for downloads). */
export async function fetchAll<T>(path: string): Promise<T[]> {
  const rows: T[] = []
  let cursor: string | null = null
  do {
    const page: Page<T> = await pageFetcher<T>(`/api/tg${withCursor(path, cursor)}`)
    rows.push(...page.items)
    cursor = page.next
  } while (cursor)
  return rows
}

/** Send an analyst decision. Returns an error message, or null when it worked. */
export async function send(path: string, body: unknown, secondToken?: string): Promise<string | null> {
  const headers: Record<string, string> = { "Content-Type": "application/json", "x-tg-request": "1" }
  if (secondToken) headers["x-second-analyst-token"] = secondToken
  try {
    const res = await fetch(`/api/tg${path}`, { method: "POST", headers, body: JSON.stringify(body) })
    return res.ok ? null : await detail(res)
  } catch {
    return "TrustGate is not reachable."
  }
}

export async function signOut() {
  await fetch("/api/session", { method: "DELETE", headers: { "x-tg-request": "1" } })
  // eslint-disable-next-line @next/next/no-location-assign-relative-destination
  window.location.assign("/login")
}
