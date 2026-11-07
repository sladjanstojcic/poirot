import { describe, expect, it } from "vitest"
import { applyDualStackDemotion, computeVerdict } from "../../src/synthesis/verdict.js"
import type { Issue, Trace } from "../../src/types/index.js"

describe("computeVerdict", () => {
  it("picks the highest severity", () => {
    const issues: Issue[] = [
      { severity: "info", code: "EMAIL_NULL_MX", message: "" },
      { severity: "warn", code: "CSP_MISSING", message: "" },
      { severity: "fail", code: "TCP_REFUSED", message: "" },
    ]
    const r = computeVerdict(issues)
    expect(r.verdict).toBe("fail")
    expect(r.worst_issues).toHaveLength(3)
    expect(r.worst_issues[0]?.code).toBe("TCP_REFUSED")
  })
})

describe("applyDualStackDemotion", () => {
  it("downgrades TCP fail on the failing stack when the other succeeded", () => {
    const trace = {
      requests: [
        {
          attempts: {
            v4: { http: { data: { status: 200 } }, tcp: { issues: [] }, tls: { issues: [] } } as any,
            v6: {
              http: { data: null },
              tcp: { issues: [{ severity: "fail", code: "TCP_UNREACHABLE", message: "x" }] },
              tls: { issues: [] },
            } as any,
          },
        },
      ],
    } as unknown as Trace
    applyDualStackDemotion(trace)
    expect(trace.requests[0]!.attempts.v6!.tcp.issues[0]!.severity).toBe("info")
  })

  it("downgrades a DNS failure on the failing stack when the other succeeded", () => {
    const trace = {
      requests: [
        {
          attempts: {
            v4: { http: { data: { status: 200 } }, dns: { issues: [] }, tcp: { issues: [] }, tls: { issues: [] } } as any,
            v6: {
              http: { data: null },
              dns: { issues: [{ severity: "fail", code: "DNS_NXDOMAIN", message: "x" }] },
              tcp: { issues: [] },
              tls: { issues: [] },
            } as any,
          },
        },
      ],
    } as unknown as Trace
    applyDualStackDemotion(trace)
    expect(trace.requests[0]!.attempts.v6!.dns.issues[0]!.severity).toBe("info")
  })
})
