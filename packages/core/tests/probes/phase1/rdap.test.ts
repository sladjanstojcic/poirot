import { performance } from "node:perf_hooks"
import { describe, expect, it, vi } from "vitest"
import { rdap } from "../../../src/probes/phase1/rdap.js"

const ctx = {
  traceStart: performance.now(),
  signal: new AbortController().signal,
  flags: {},
  cache: new Map(),
  logger: () => {},
}

describe("rdap probe", () => {
  it("returns skipped when domain is blank", async () => {
    const r = await rdap({ domain: "" }, ctx)
    expect(r.status).toBe("fail")
  })

  it("parses a stub RDAP response into RdapResult (registrar, events)", async () => {
    const mock = vi.fn<typeof fetch>(async (url) => {
      if (String(url).includes("data.iana.org")) {
        return new Response(
          JSON.stringify({
            services: [[["com"], ["https://rdap.example.test/"]]],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        )
      }
      return new Response(
        JSON.stringify({
          entities: [{ roles: ["registrar"], vcardArray: [["vcard"], [["fn", {}, "text", "Test Registrar"]]] }],
          events: [
            { eventAction: "registration", eventDate: "2020-01-01T00:00:00Z" },
            { eventAction: "expiration", eventDate: "2030-01-01T00:00:00Z" },
          ],
          nameservers: [{ ldhName: "NS1.TEST" }],
          status: ["active"],
        }),
        { status: 200, headers: { "content-type": "application/rdap+json" } },
      )
    })
    const globalRef = globalThis as any
    const previousFetch = globalRef.fetch
    globalRef.fetch = mock
    try {
      const r = await rdap({ domain: "example.com" }, ctx)
      expect(r.status).toBe("pass")
      expect(r.data?.registrar).toBe("Test Registrar")
      expect(r.data?.nameservers).toEqual(["ns1.test"])
      expect(r.data?.age_days).toBeGreaterThan(0)
    } finally {
      globalRef.fetch = previousFetch
    }
  })
})
