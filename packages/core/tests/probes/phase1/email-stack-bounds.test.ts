import { performance } from "node:perf_hooks"
import { describe, expect, it, vi } from "vitest"

vi.mock("mailauth", () => ({
  spf: vi.fn(async () => ({ rr: "v=spf1 -all", lookups: { limit: 10, count: 0, void: 0 } })),
  dmarc: vi.fn(async () => ({ policy: "reject" })),
  bimi: vi.fn(async () => ({})),
}))
vi.mock("mailauth/lib/mta-sts.js", () => ({ getPolicy: vi.fn(async () => ({ status: "not_found" })) }))
vi.mock("../../../src/net/dns-packet.js", () => ({ dnsQuery: vi.fn(async () => ({ answers: [] })) }))

import { spf } from "mailauth"
import { emailStack } from "../../../src/probes/phase1/email-stack.js"

const dns = { resolver: "1.1.1.1", a: [], aaaa: [], mx: [{ host: "mx.ex.test", priority: 10 }], txt: [], ns: [], caa: [], dnssec: { signed: false } } as any
const ctx = (signal = new AbortController().signal) => ({ traceStart: performance.now(), signal, flags: {}, cache: new Map(), logger: () => {} })

describe("emailStack", () => {
  it("SPF record is read from mailauth's rr field", async () => {
    const r = await emailStack({ domain: "ex.test", dns, dkim_selectors: [] }, ctx())
    expect(r.issues.some((issue) => issue.code === "SPF_MISSING")).toBe(false)
    expect(r.data?.spf?.record).toBe("v=spf1 -all")
  })

  it("a mailauth lookup that never settles is bounded by the signal", async () => {
    vi.mocked(spf).mockImplementationOnce(() => new Promise(() => {}))
    const controller = new AbortController()
    setTimeout(() => controller.abort(new Error("POIROT_DEADLINE")), 200)
    const t0 = Date.now()
    const r = await emailStack({ domain: "ex.test", dns, dkim_selectors: [] }, ctx(controller.signal))
    expect(Date.now() - t0).toBeLessThan(1500)
    expect(r.issues.some((issue) => issue.code === "DNS_TIMEOUT")).toBe(true)
  })
})
