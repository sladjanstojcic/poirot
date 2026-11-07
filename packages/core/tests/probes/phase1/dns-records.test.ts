import { performance } from "node:perf_hooks"
import { describe, expect, it, vi } from "vitest"
import * as netDns from "../../../src/net/dns-packet.js"
import { dnsRecords } from "../../../src/probes/phase1/dns-records.js"

const ctx = {
  traceStart: performance.now(),
  signal: new AbortController().signal,
  flags: {},
  cache: new Map(),
  logger: () => {},
}

// Helper to build a minimal dns-packet-shaped reply
function answer(type: string, data: unknown) {
  return { name: "example.com", type, class: "IN", ttl: 300, data }
}

describe("dnsRecords probe", () => {
  it("collects A/AAAA/MX/NS/CAA/TXT into shaped output", async () => {
    const spy = vi.spyOn(netDns, "dnsQuery").mockImplementation(async (_name, type) => ({
      id: 0,
      type: "response",
      flags: 0,
      questions: [],
      answers:
        type === "A"
          ? [answer("A", "1.2.3.4")]
          : type === "AAAA"
            ? [answer("AAAA", "::1")]
            : type === "MX"
              ? [answer("MX", { exchange: "mx.example.com", preference: 10 })]
              : type === "NS"
                ? [answer("NS", "ns1.example.com")]
                : type === "CAA"
                  ? [answer("CAA", { flags: 0, tag: "issue", value: "letsencrypt.org" })]
                  : type === "TXT"
                    ? [answer("TXT", [Buffer.from("v=spf1 -all")])]
                    : [],
    }) as any)
    const r = await dnsRecords({ domain: "example.com" }, ctx)
    spy.mockRestore()
    expect(r.status).toBe("pass")
    expect(r.data?.a).toEqual(["1.2.3.4"])
    expect(r.data?.aaaa).toEqual(["::1"])
    expect(r.data?.mx).toEqual([{ host: "mx.example.com", priority: 10 }])
    expect(r.data?.ns).toEqual(["ns1.example.com"])
    expect(r.data?.caa).toEqual([{ flag: 0, tag: "issue", value: "letsencrypt.org" }])
    expect(r.data?.txt).toEqual(["v=spf1 -all"])
  })

  it("emits DOMAIN_NO_ADDRESS when A and AAAA empty", async () => {
    const spy = vi.spyOn(netDns, "dnsQuery").mockResolvedValue({
      id: 0,
      type: "response",
      flags: 0,
      questions: [],
      answers: [],
    } as any)
    const r = await dnsRecords({ domain: "nowhere.test" }, ctx)
    spy.mockRestore()
    expect(r.status).toBe("fail")
    expect(r.issues.map((issue) => issue.code)).toContain("DOMAIN_NO_ADDRESS")
  })

  it("reports DNS timeouts instead of DOMAIN_NO_ADDRESS when address queries fail", async () => {
    const spy = vi.spyOn(netDns, "dnsQuery").mockRejectedValue(new Error("DNS_TIMEOUT"))
    const r = await dnsRecords({ domain: "example.com" }, ctx)
    spy.mockRestore()
    const codes = r.issues.map((issue) => issue.code)
    expect(r.status).toBe("fail")
    expect(codes).toContain("DNS_TIMEOUT")
    expect(codes).not.toContain("DOMAIN_NO_ADDRESS")
  })

  it("retries timed-out address queries before reporting DNS failure", async () => {
    let aQueries = 0
    const spy = vi.spyOn(netDns, "dnsQuery").mockImplementation(async (_name, type) => {
      if (type === "A") {
        aQueries += 1
        if (aQueries === 1) throw new Error("DNS_TIMEOUT")
        return {
          id: 0,
          type: "response",
          flags: 0,
          questions: [],
          answers: [answer("A", "1.2.3.4")],
        } as any
      }
      return {
        id: 0,
        type: "response",
        flags: 0,
        questions: [],
        answers: [],
      } as any
    })

    const r = await dnsRecords({ domain: "example.com" }, ctx)
    spy.mockRestore()
    const codes = r.issues.map((issue) => issue.code)
    expect(r.status).toBe("pass")
    expect(r.data?.a).toEqual(["1.2.3.4"])
    expect(codes).not.toContain("DNS_TIMEOUT")
    expect(codes).not.toContain("DOMAIN_NO_ADDRESS")
  })

  it("unresponsive resolver: one round of queries, no retry, no DNSKEY", async () => {
    const spy = vi.spyOn(netDns, "dnsQuery").mockRejectedValue(new Error("DNS_TIMEOUT"))
    const r = await dnsRecords({ domain: "example.com" }, ctx)
    const types = spy.mock.calls.map((call) => call[1])
    expect(types).not.toContain("DNSKEY")
    expect(new Set(types).size).toBe(types.length)
    expect(r.issues.some((issue) => issue.code === "DNS_TIMEOUT")).toBe(true)
    spy.mockRestore()
  })
})
