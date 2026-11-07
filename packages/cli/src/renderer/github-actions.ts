import type { Issue, Trace } from "@poirot/core"

const LEVEL: Record<Issue["severity"], string> = { fail: "error", warn: "warning", info: "notice" }

function collect(trace: Trace): Issue[] {
  const out: Issue[] = []
  const put = (items?: Issue[]) => {
    if (items) out.push(...items)
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

  return out
}

export function renderGithubActions(trace: Trace): string {
  const lines: string[] = []
  for (const issue of collect(trace)) {
    const level = LEVEL[issue.severity]
    const message = issue.message.replace(/\r?\n/g, " ")
    lines.push(`::${level} title=${issue.code}::${issue.severity}  ${message}  (${trace.domain.domain})`)
  }
  return lines.join("\n")
}
