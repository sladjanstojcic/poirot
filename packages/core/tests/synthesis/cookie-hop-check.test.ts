import { describe, expect, it } from "vitest"
import { cookieHopCheck } from "../../src/synthesis/cookie-hop-check.js"

describe("cookieHopCheck", () => {
  it("flags Secure cookie set on an http:// hop", () => {
    const trace: any = {
      requests: [
        { url: "http://ex.test/", audits: { cookies: { data: { cookies: [{ name: "sid", secure: true }] } } } },
        { url: "https://ex.test/", audits: { cookies: { data: { cookies: [] } } } },
      ],
    }
    const r = cookieHopCheck(trace)
    expect(r).toHaveLength(1)
    expect(r[0]?.code).toBe("COOKIE_SECURE_ON_HTTP_HOP")
  })

  it("no issue for pure https chain", () => {
    const trace: any = {
      requests: [
        { url: "https://ex.test/", audits: { cookies: { data: { cookies: [{ name: "sid", secure: true }] } } } },
      ],
    }
    expect(cookieHopCheck(trace)).toEqual([])
  })
})
