import type { Synthesis, Trace } from "../types/index.js"

const sum = (nums: number[]) => nums.reduce((acc, value) => acc + value, 0)
const max = (nums: number[]) => (nums.length ? Math.max(...nums) : 0)

export function computeTimings(trace: Trace): Synthesis["timings"] {
  const phase1 = sum([
    trace.domain.rdap.timing.duration_ms,
    trace.domain.dns.timing.duration_ms,
    trace.domain.email.timing.duration_ms,
  ])

  const network = sum(
    trace.requests.map((request) => {
      const attempts = [request.attempts.v4, request.attempts.v6].filter(Boolean) as Array<{ http: { timing: { duration_ms: number } } }>
      return max(attempts.map((attempt) => attempt.http?.timing?.duration_ms ?? 0))
    }),
  )

  const audits = sum(
    trace.requests.map((request) =>
      max(Object.values(request.audits).map((audit) => audit.timing.duration_ms)),
    ),
  )

  const slowest_hop = trace.requests
    .map((request) => ({ url: request.url, duration_ms: request.timing.duration_ms }))
    .sort((a, b) => b.duration_ms - a.duration_ms)[0]

  return {
    total_ms: trace.duration_ms,
    by_phase: {
      hostname_context_ms: phase1,
      network_ms: network,
      audits_ms: audits,
      synthesis_ms: 0,
    },
    slowest_hop,
  }
}
