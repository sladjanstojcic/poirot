import type { Issue, Trace } from "@poirot/core"

/** Every issue in a trace: domain, each attempt's stages, audits, synthesis. */
export function collectIssues(trace: Trace): Issue[] {
  const out: Issue[] = []
  const put = (issues?: Issue[]) => {
    if (issues) out.push(...issues)
  }

  put(trace.domain.rdap.issues)
  put(trace.domain.dns.issues)
  put(trace.domain.email.issues)
  for (const request of trace.requests) {
    for (const stack of ["v4", "v6"] as const) {
      const attempt = request.attempts[stack]
      if (!attempt) continue
      put(attempt.dns.issues)
      put(attempt.tcp.issues)
      put(attempt.tls.issues)
      put(attempt.http.issues)
      if (attempt.quic) put(attempt.quic.issues)
    }
    for (const audit of Object.values(request.audits)) put(audit.issues)
  }
  put(trace.synthesis.worst_issues)
  return out
}
