import type { Issue, Trace } from "../types/index.js"

const SEVERITY_RANK = { fail: 3, warn: 2, info: 1 } as const

export function computeVerdict(issues: Issue[]): { verdict: "pass" | "warn" | "fail"; worst_issues: Issue[] } {
  const verdict = issues.some((issue) => issue.severity === "fail")
    ? "fail"
    : issues.some((issue) => issue.severity === "warn")
      ? "warn"
      : "pass"

  const worst_issues = [...issues]
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])
    .slice(0, 3)

  return { verdict, worst_issues }
}

// Failures confined to one stack while the other answered: usually the probing
// machine's network (no IPv6 route, broken resolver for one family), not the site.
const DEMOTABLE_CODES = new Set([
  "DNS_TIMEOUT",
  "DNS_UNREACHABLE",
  "DNS_SERVFAIL",
  "DNS_NXDOMAIN",
  "TCP_REFUSED",
  "TCP_UNREACHABLE",
  "TCP_TIMEOUT",
  "TCP_ERROR",
  "TLS_TIMEOUT",
  "HTTP_TIMEOUT",
])

export function applyDualStackDemotion(trace: Trace): void {
  for (const request of trace.requests) {
    const v4Ok = request.attempts.v4?.http?.data != null
    const v6Ok = request.attempts.v6?.http?.data != null
    if (v4Ok === v6Ok) continue

    const failing = v4Ok ? request.attempts.v6 : request.attempts.v4
    if (!failing) continue

    for (const probe of [failing.dns, failing.tcp, failing.tls, failing.http]) {
      if (!probe?.issues) continue
      for (const issue of probe.issues) {
        if (DEMOTABLE_CODES.has(issue.code)) issue.severity = "info"
      }
    }
  }
}

export function collectAllIssues(trace: Trace): Issue[] {
  const out: Issue[] = []
  const visit = (items?: Issue[]) => {
    if (items) out.push(...items)
  }

  visit(trace.domain.rdap.issues)
  visit(trace.domain.dns.issues)
  visit(trace.domain.email.issues)

  for (const request of trace.requests) {
    for (const stack of ["v4", "v6"] as const) {
      const attempt = request.attempts[stack]
      if (!attempt) continue
      visit(attempt.dns.issues)
      visit(attempt.tcp.issues)
      visit(attempt.tls.issues)
      visit(attempt.http.issues)
      if (attempt.quic) visit(attempt.quic.issues)
    }
    for (const audit of Object.values(request.audits)) visit(audit.issues)
  }

  return out
}
