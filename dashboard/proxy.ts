import { NextResponse, type NextRequest } from "next/server"

// Pages need a session; the sign-in page and the API decide for themselves.
export function proxy(request: NextRequest) {
  if (!request.cookies.get("tg_session")) {
    return NextResponse.redirect(new URL("/login", request.url))
  }
  return NextResponse.next()
}

export const config = {
  matcher: ["/((?!api|login|_next/static|_next/image|icon.svg|robots.txt).*)"],
}
