import type { NetworkAttempt, Trace } from "@poirot/core"

/** Per-URL exit codes from spec 05 §4 (1 and 2 are decided by the CLI itself). */
export const EXIT = { OK: 0, GATE: 1, USAGE: 2, DNS: 3, TLS: 4, NETWORK: 5, TIMEOUT: 6, SIGINT: 130 } as const

type Stage = "dns" | "tcp" | "tls" | "http"

/** First stage of an attempt that failed, with its issue codes. */
function failingStage(attempt: NetworkAttempt): { stage: Stage; codes: string[] } | undefined {
  for (const stage of ["dns", "tcp", "tls", "http"] as const) {
    const result = attempt[stage]
    const failed = result.status === "fail" || ((stage === "tls" || stage === "http") && result.status !== "skipped" && !result.data)
    if (failed) return { stage, codes: result.issues.map((issue) => issue.code) }
  }
  return undefined
}

/**
 * Classify why the final hop got no response: 0 (it did), 3 DNS, 4 TLS,
 * 5 network, 6 timeout. A timeout anywhere wins, since it says the deadline,
 * not the target, ended the run.
 */
export function traceExitCode(trace: Trace): 0 | 3 | 4 | 5 | 6 {
  const request = trace.requests[trace.requests.length - 1]
  if (!request || request.response) return EXIT.OK

  const failures = [request.attempts.v4, request.attempts.v6]
    .filter((attempt): attempt is NetworkAttempt => attempt != null)
    .map(failingStage)
    .filter((failure) => failure != null)

  const domainDnsCodes = trace.domain.dns.issues.map((issue) => issue.code)
  if (failures.length === 0) return domainDnsCodes.includes("DNS_TIMEOUT") ? EXIT.TIMEOUT : EXIT.DNS
  if (failures.some((failure) => failure.codes.some((code) => code.endsWith("_TIMEOUT")))) return EXIT.TIMEOUT
  if (failures.every((failure) => failure.stage === "dns")) return EXIT.DNS
  if (failures.some((failure) => failure.stage === "tls")) return EXIT.TLS
  return EXIT.NETWORK
}
