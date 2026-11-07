import { caaCrossCheck } from "../synthesis/caa-cross-check.js"
import { computeHash } from "../synthesis/change-hash.js"
import { cookieHopCheck } from "../synthesis/cookie-hop-check.js"
import { computeGrade } from "../synthesis/grade.js"
import { computeTimings } from "../synthesis/timings.js"
import { applyDualStackDemotion, collectAllIssues, computeVerdict } from "../synthesis/verdict.js"
import type { Issue, Synthesis, Trace } from "../types/index.js"
import { AUDIT_ALGORITHM_VERSION } from "../version.js"
import { collectAlertables } from "./collect-alertables.js"

export function synthesize(trace: Trace): Synthesis {
  applyDualStackDemotion(trace)

  const extraIssues: Issue[] = []
  const firstRequest = trace.requests[0]
  const primaryTls = firstRequest?.attempts.v4?.tls.data ?? firstRequest?.attempts.v6?.tls.data
  if (primaryTls && trace.domain.dns.data) {
    const issue = caaCrossCheck(trace.domain.dns.data.caa, primaryTls.cert_leaf.issuer)
    if (issue) extraIssues.push(issue)
  }
  extraIssues.push(...cookieHopCheck(trace))

  const allIssues = [...collectAllIssues(trace), ...extraIssues]
  const headersForGrade = firstRequest?.audits.headers.data
  const verdict = computeVerdict(allIssues)
  const { grade, score } = computeGrade(allIssues, headersForGrade)
  const timings = computeTimings(trace)
  const alertables = collectAlertables(trace)

  // No response on the final hop: nothing was served, so the run fails outright.
  // (Penalty-based grading would otherwise score an unreachable site 100/A.)
  const noResponse = trace.requests.length > 0 && !trace.requests[trace.requests.length - 1]!.response

  return {
    verdict: noResponse ? "fail" : verdict.verdict,
    grade: noResponse ? "F" : grade,
    score: noResponse ? 0 : score,
    worst_issues: verdict.worst_issues,
    timings,
    change_hash: computeHash(alertables),
    change_fields: Object.keys(alertables).sort(),
    audit_algorithm_version: AUDIT_ALGORITHM_VERSION,
  }
}
