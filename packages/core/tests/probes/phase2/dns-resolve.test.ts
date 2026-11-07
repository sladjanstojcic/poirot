import dns from "node:dns"
import { performance } from "node:perf_hooks"
import { describe, expect, it, vi } from "vitest"
import * as netDns from "../../../src/net/dns-packet.js"
import { dnsResolve } from "../../../src/probes/phase2/dns-resolve.js"

const ctx = {
  traceStart: performance.now(),
  signal: new AbortController().signal,
  flags: {},
  cache: new Map(),
  logger: () => {},
}

describe("dnsResolve", () => {
  it("picks the first A record for v4", async () => {
    vi.spyOn(netDns, "dnsQuery").mockResolvedValue({
      id: 0,
      type: "response",
      flags: 0,
      questions: [],
      answers: [
        { name: "h", type: "A", class: "IN", ttl: 300, data: "1.2.3.4" },
        { name: "h", type: "A", class: "IN", ttl: 300, data: "5.6.7.8" },
      ],
    } as any)
    const r = await dnsResolve({ hostname: "h.test", stack: "v4", resolver: "1.1.1.1" }, ctx)
    expect(r.status).toBe("pass")
    expect(r.data?.chosen_ip).toBe("1.2.3.4")
    expect(r.data?.all_answers).toEqual(["1.2.3.4", "5.6.7.8"])
  })

  it("returns skipped when stack has no answers", async () => {
    vi.spyOn(netDns, "dnsQuery").mockResolvedValue({
      id: 0,
      type: "response",
      flags: 0,
      questions: [],
      answers: [],
    } as any)
    const r = await dnsResolve({ hostname: "h.test", stack: "v6", resolver: "1.1.1.1" }, ctx)
    expect(r.status).toBe("skipped")
    expect(r.skipped?.reason).toBe("not_applicable")
  })

  it("no resolver uses the OS (localhost resolves)", async () => {
    vi.restoreAllMocks()
    const r = await dnsResolve({ hostname: "localhost", stack: "v4" }, ctx)
    expect(r.status).toBe("pass")
    expect(r.data?.chosen_ip).toBe("127.0.0.1")
    expect(r.data?.resolver).toBe("system")
  })

  it("no resolver, unknown host → DNS_NXDOMAIN", async () => {
    vi.restoreAllMocks()
    const r = await dnsResolve({ hostname: "poirot-nonexistent.invalid", stack: "v4" }, ctx)
    expect(r.status).toBe("fail")
    expect(r.issues[0]?.code).toBe("DNS_NXDOMAIN")
  })

  it("v6 system lookup ignores IPv4-mapped addresses", async () => {
    vi.restoreAllMocks()
    vi.spyOn(dns.promises, "lookup").mockResolvedValue([{ address: "::ffff:140.82.121.3", family: 6 }] as any)
    const r = await dnsResolve({ hostname: "github.com", stack: "v6" }, ctx)
    expect(r.status).toBe("skipped")
  })

  it("v6 ENOTFOUND for a name that has IPv4 is no answer, not NXDOMAIN (glibc)", async () => {
    vi.restoreAllMocks()
    vi.spyOn(dns.promises, "lookup").mockImplementation((async (_host: string, opts: any) => {
      if (opts?.family === 6) throw Object.assign(new Error("getaddrinfo ENOTFOUND github.com"), { code: "ENOTFOUND" })
      return [{ address: "140.82.121.3", family: 4 }]
    }) as any)
    const r = await dnsResolve({ hostname: "github.com", stack: "v6" }, ctx)
    expect(r.status).toBe("skipped")
  })
})
