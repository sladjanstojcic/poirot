import type { Issue, Trace } from "../types/index.js"

export function cookieHopCheck(trace: Trace): Issue[] {
  const out: Issue[] = []
  for (const [index, request] of trace.requests.entries()) {
    let parsed: URL
    try {
      parsed = new URL(request.url)
    } catch {
      continue
    }
    if (parsed.protocol !== "http:") continue

    const cookies = request.audits?.cookies?.data?.cookies ?? []
    for (const cookie of cookies) {
      if (!cookie.secure) continue
      out.push({
        severity: "fail",
        code: "COOKIE_SECURE_ON_HTTP_HOP",
        message: `hop ${index}: cookie "${cookie.name}" has Secure on HTTP`,
        at: `requests[${index}]`,
      })
    }
  }
  return out
}
