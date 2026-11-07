import { describe, expect, it } from "vitest"
import type { Issue, NetworkAttempt, Trace } from "@poirot/core"
import { traceExitCode } from "../src/exit-code.js"

type Stage = { status: "pass" | "fail" | "skipped" | "warn"; issues?: Issue[]; data?: object }
const pass: Stage = { status: "pass", data: {} }
const skipped: Stage = { status: "skipped" }
const failWith = (code: string): Stage => ({ status: "fail", issues: [{ severity: "fail", code, message: code }] })

function attempt(stages: Partial<Record<"dns" | "tcp" | "tls" | "http", Stage>>): NetworkAttempt {
  const result = (s: Stage | undefined) => ({ issues: [], timing: { startedAt_ms: 0, duration_ms: 0 }, alertable_fields: [], ...(s ?? skipped) })
  return { dns: result(stages.dns), tcp: result(stages.tcp), tls: result(stages.tls), http: result(stages.http) } as any
}

function trace(opts: { response?: boolean; v4?: NetworkAttempt; v6?: NetworkAttempt; domainDnsIssues?: Issue[] }): Trace {
  return {
    domain: { dns: { status: "pass", issues: opts.domainDnsIssues ?? [] } },
    requests: [{ attempts: { v4: opts.v4, v6: opts.v6 }, response: opts.response ? { status: 200 } : undefined }],
  } as any
}

describe("traceExitCode", () => {
  it("response present → 0", () => {
    expect(traceExitCode(trace({ response: true, v4: attempt({ dns: pass, tcp: pass, http: pass }) }))).toBe(0)
  })
  it("no attempts → 3", () => {
    expect(traceExitCode(trace({}))).toBe(3)
  })
  it("no attempts + DNS_TIMEOUT → 6", () => {
    expect(traceExitCode(trace({ domainDnsIssues: [{ severity: "fail", code: "DNS_TIMEOUT", message: "t" }] }))).toBe(6)
  })
  it("dns failed on every attempt → 3", () => {
    expect(traceExitCode(trace({ v4: attempt({ dns: failWith("DNS_NXDOMAIN") }) }))).toBe(3)
  })
  it("dns timed out → 6", () => {
    expect(traceExitCode(trace({ v4: attempt({ dns: failWith("DNS_TIMEOUT") }) }))).toBe(6)
  })
  it("tcp TCP_REFUSED on both stacks → 5", () => {
    const v4 = attempt({ dns: pass, tcp: failWith("TCP_REFUSED") })
    const v6 = attempt({ dns: pass, tcp: failWith("TCP_UNREACHABLE") })
    expect(traceExitCode(trace({ v4, v6 }))).toBe(5)
  })
  it("tcp TCP_TIMEOUT → 6", () => {
    expect(traceExitCode(trace({ v4: attempt({ dns: pass, tcp: failWith("TCP_TIMEOUT") }) }))).toBe(6)
  })
  it("tls failed (no tls.data) → 4", () => {
    expect(traceExitCode(trace({ v4: attempt({ dns: pass, tcp: pass, tls: failWith("PROBE_THREW") }) }))).toBe(4)
  })
  it("http failed after tls → 5", () => {
    expect(traceExitCode(trace({ v4: attempt({ dns: pass, tcp: pass, tls: pass, http: failWith("HTTP_RESET") }) }))).toBe(5)
  })
  it("exit 0 when v4 succeeds and v6 is unreachable", () => {
    const v4 = attempt({ dns: pass, tcp: pass, http: pass })
    const v6 = attempt({ dns: pass, tcp: { status: "fail", issues: [{ severity: "info", code: "TCP_UNREACHABLE", message: "x" }] } })
    expect(traceExitCode(trace({ response: true, v4, v6 }))).toBe(0)
  })
  it("exit 0 when phase-1 DNS fails but the request got a response", () => {
    const t = trace({ response: true, v4: attempt({ dns: pass, tcp: pass, http: pass }), domainDnsIssues: [{ severity: "fail", code: "DNS_TIMEOUT", message: "t" }] })
    expect(traceExitCode(t)).toBe(0)
  })
})
