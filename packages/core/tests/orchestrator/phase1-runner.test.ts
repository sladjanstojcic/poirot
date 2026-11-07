import { performance } from "node:perf_hooks"
import { afterEach, describe, expect, it, vi } from "vitest"

// Phase-1 record and email probes are network-heavy; stub them so this test
// isolates which domain each probe receives.
const dnsResult = { current: {} as any }
vi.mock("../../src/probes/phase1/dns-records.js", () => ({
  dnsRecords: vi.fn(async () => dnsResult.current),
}))
vi.mock("../../src/probes/phase1/email-stack.js", () => ({
  emailStack: vi.fn(async () => ({ status: "pass", data: {}, issues: [], timing: { startedAt_ms: 0, duration_ms: 0 }, alertable_fields: [] })),
}))

import { emailStack } from "../../src/probes/phase1/email-stack.js"
import { runPhase1 } from "../../src/orchestrator/phase1-runner.js"

const ctx = {
  traceStart: performance.now(),
  signal: new AbortController().signal,
  flags: {},
  cache: new Map(),
  logger: () => {},
}

const okDns = { status: "pass", data: { a: [], aaaa: [], mx: [], ns: [], txt: [], caa: [], dnssec: { signed: false } }, issues: [], timing: { startedAt_ms: 0, duration_ms: 0 }, alertable_fields: [] }

afterEach(() => {
  vi.unstubAllGlobals()
  vi.mocked(emailStack).mockClear()
})

describe("runPhase1", () => {
  it("rdap is queried with the registrable domain", async () => {
    dnsResult.current = okDns
    const urls: string[] = []
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        urls.push(String(url))
        if (String(url).includes("data.iana.org")) {
          return new Response(JSON.stringify({ services: [[["com"], ["https://rdap.example.test/"]]] }), { status: 200 })
        }
        return new Response("{}", { status: 404 })
      }),
    )
    await runPhase1({ domain: "www.example.com", registrableDomain: "example.com", dkimSelectors: [] }, ctx as any)
    expect(urls.some((url) => url.endsWith("/domain/example.com"))).toBe(true)
    expect(urls.some((url) => url.endsWith("/domain/www.example.com"))).toBe(false)
  })

  it("NXDOMAIN skips email checks", async () => {
    dnsResult.current = {
      status: "fail",
      data: { a: [], aaaa: [], mx: [], ns: [], txt: [], caa: [], dnssec: { signed: false } },
      issues: [{ severity: "fail", code: "DNS_NXDOMAIN", message: "nx" }],
      timing: { startedAt_ms: 0, duration_ms: 0 },
      alertable_fields: [],
    }
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 404 })))
    const r = await runPhase1({ domain: "nope.example", registrableDomain: "nope.example", dkimSelectors: [] }, ctx as any)
    expect(r.email.status).toBe("skipped")
    expect(vi.mocked(emailStack)).not.toHaveBeenCalled()
  })
})
