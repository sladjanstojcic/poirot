import { performance } from "node:perf_hooks"
import { describe, expect, it, vi } from "vitest"
import type { DnsRecords } from "../../../src/types/index.js"

// Mock mailauth + dnsQuery BEFORE importing the probe (vitest hoists vi.mock).
vi.mock("mailauth", () => ({
  spf: vi.fn(async () => ({})),
  dmarc: vi.fn(async () => ({})),
  bimi: vi.fn(async () => ({})),
}))
vi.mock("mailauth/lib/mta-sts.js", () => ({
  getPolicy: vi.fn(async () => ({ status: "not_found" })),
}))
vi.mock("../../../src/net/dns-packet.js", () => ({
  dnsQuery: vi.fn(async () => ({
    id: 0,
    type: "response",
    flags: 0,
    questions: [],
    answers: [],
  })),
}))

import { emailStack } from "../../../src/probes/phase1/email-stack.js"

const ctx = {
  traceStart: performance.now(),
  signal: new AbortController().signal,
  flags: {},
  cache: new Map(),
  logger: () => {},
}

function dns(partial: Partial<DnsRecords>): DnsRecords {
  return {
    resolver: "1.1.1.1",
    a: [],
    aaaa: [],
    mx: [],
    txt: [],
    ns: [],
    caa: [],
    dnssec: { signed: false, rrsig_present: false, ds_present_at_parent: false, dnskey_present: false },
    queries_made: 0,
    total_ms: 0,
    ...partial,
  }
}

describe("emailStack probe", () => {
  it("short-circuits on null MX", async () => {
    const r = await emailStack(
      {
        domain: "example.com",
        dns: dns({ mx: [{ host: ".", priority: 0 }] }),
        dkim_selectors: [],
      },
      ctx,
    )
    expect(r.data?.null_mx).toBe(true)
    expect(r.issues.map((issue) => issue.code)).toContain("EMAIL_NULL_MX")
  })

  it("emits SPF_MISSING + DMARC_MISSING + MTA_STS_MISSING when none published", async () => {
    const r = await emailStack(
      {
        domain: "example.com",
        dns: dns({ mx: [{ host: "mx.example.com", priority: 10 }] }),
        dkim_selectors: [],
      },
      ctx,
    )
    const codes = r.issues.map((issue) => issue.code)
    expect(codes).toContain("SPF_MISSING")
    expect(codes).toContain("DMARC_MISSING")
    expect(codes).toContain("MTA_STS_MISSING")
    expect(r.data?.null_mx).toBe(false)
    expect(r.status).toBe("warn")
  })

  it("emits SPF_LOOKUP_LIMIT_EXCEEDED when SPF chain > 10 lookups", async () => {
    const { spf } = await import("mailauth")
    ;(spf as any).mockResolvedValueOnce({
      rr: "v=spf1 include:a include:b -all", // mailauth returns the record as `rr`
      lookups: { count: 11, limit: 10, void: 0 },
    })
    const r = await emailStack(
      {
        domain: "example.com",
        dns: dns({ mx: [{ host: "mx.example.com", priority: 10 }] }),
        dkim_selectors: [],
      },
      ctx,
    )
    expect(r.issues.map((issue) => issue.code)).toContain("SPF_LOOKUP_LIMIT_EXCEEDED")
    expect(r.status).toBe("fail")
  })

  it("resolves DKIM selectors via dnsQuery and flags malformed records", async () => {
    const { dnsQuery } = await import("../../../src/net/dns-packet.js")
    const mk = (txt: string) => ({
      id: 0,
      type: "response",
      flags: 0,
      questions: [],
      answers: [{ name: "x", type: "TXT", class: "IN", ttl: 60, data: txt }],
    })
    ;(dnsQuery as any)
      .mockResolvedValueOnce(mk("v=DKIM1; k=rsa; p=MIIBIjANBgkqh"))
      .mockResolvedValueOnce(mk("bogus-record-no-v-tag"))
      .mockResolvedValueOnce({ id: 0, type: "response", flags: 0, questions: [], answers: [] })
    const r = await emailStack(
      {
        domain: "example.com",
        dns: dns({ mx: [{ host: "mx.example.com", priority: 10 }] }),
        dkim_selectors: ["good", "bad", "missing"],
      },
      ctx,
    )
    expect(r.data?.dkim.good?.valid).toBe(true)
    expect(r.data?.dkim.bad?.valid).toBe(false)
    expect(r.data?.dkim.missing).toBeUndefined()
    expect(r.issues.map((issue) => issue.code)).toContain("DKIM_MALFORMED")
  })

describe("emailStack resolver", () => {
  it("uses the given resolver", async () => {
    const { dnsQuery } = await import("../../../src/net/dns-packet.js")
    vi.mocked(dnsQuery).mockClear()
    await emailStack({ domain: "ex.test", dns: dns({}), dkim_selectors: ["s1"], resolver: "9.9.9.9" } as any, ctx)
    expect(vi.mocked(dnsQuery).mock.calls.length).toBeGreaterThan(0)
    expect(vi.mocked(dnsQuery).mock.calls.every((call) => call[2] === "9.9.9.9")).toBe(true)
  })
})
})