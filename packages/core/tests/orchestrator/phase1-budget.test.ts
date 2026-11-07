import { performance } from "node:perf_hooks"
import { afterEach, describe, expect, it, vi } from "vitest"

// emailStack stands in for a slow mailauth/DNS environment: it only returns
// once its signal aborts. dnsRecords reports either success or a dead resolver.
const dnsResult = { current: {} as any }
vi.mock("../../src/probes/phase1/dns-records.js", () => ({ dnsRecords: vi.fn(async () => dnsResult.current) }))
vi.mock("../../src/probes/phase1/email-stack.js", () => ({
  emailStack: vi.fn(
    (_input: any, ctx: any) =>
      new Promise((resolve) => {
        const done = () =>
          resolve({ status: "skipped", issues: [], timing: { startedAt_ms: 0, duration_ms: 0 }, skipped: { reason: "upstream_failed" }, alertable_fields: [] })
        if (ctx.signal.aborted) done()
        else ctx.signal.addEventListener("abort", done)
      }),
  ),
}))

import { emailStack } from "../../src/probes/phase1/email-stack.js"
import { runPhase1 } from "../../src/orchestrator/phase1-runner.js"

const ctx = () => ({ traceStart: performance.now(), signal: new AbortController().signal, flags: {}, cache: new Map(), logger: () => {} })
const records = (issues: any[] = []) => ({
  status: issues.length ? "fail" : "pass",
  data: { a: [], aaaa: [], mx: [], ns: [], txt: [], caa: [], dnssec: { signed: false } },
  issues,
  timing: { startedAt_ms: 0, duration_ms: 0 },
  alertable_fields: [],
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.mocked(emailStack).mockClear()
})

describe("phase 1 budget", () => {
  it("phase 1 ends at its own budget even when a probe never finishes", async () => {
    dnsResult.current = records()
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 404 })))
    const t0 = Date.now()
    await runPhase1({ domain: "example.com", registrableDomain: "example.com", dkimSelectors: [], budgetMs: 300 }, ctx() as any)
    expect(Date.now() - t0).toBeLessThan(1500)
  })

  it("unusable resolver skips email checks", async () => {
    dnsResult.current = records([
      { severity: "fail", code: "DNS_TIMEOUT", message: "t" },
      { severity: "fail", code: "DNS_UNREACHABLE", message: "u" },
    ])
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 404 })))
    const r = await runPhase1({ domain: "example.com", registrableDomain: "example.com", dkimSelectors: [], budgetMs: 5000 }, ctx() as any)
    expect(vi.mocked(emailStack)).not.toHaveBeenCalled()
    expect(r.email.status).toBe("skipped")
  })

  it("aborted RDAP lookup is RDAP_UNREACHABLE, not PROBE_THREW", async () => {
    dnsResult.current = records()
    vi.stubGlobal(
      "fetch",
      vi.fn((_url: string, init: any) => new Promise((_, reject) => init.signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError"))))),
    )
    const r = await runPhase1({ domain: "example.com", registrableDomain: "example.com", dkimSelectors: [], budgetMs: 300 }, ctx() as any)
    expect(r.rdap.issues[0]?.code).toBe("RDAP_UNREACHABLE")
  })
})
