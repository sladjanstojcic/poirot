import { performance } from "node:perf_hooks"
import { describe, expect, it } from "vitest"
import { cookieAudit } from "../../../src/probes/phase3/cookie-audit.js"

const ctx = {
  traceStart: performance.now(),
  signal: new AbortController().signal,
  flags: {},
  cache: new Map(),
  logger: () => {},
}

describe("cookieAudit", () => {
  it("flags COOKIE_NO_SECURE on https", async () => {
    const r = await cookieAudit(
      {
        headers: [["set-cookie", "sid=abc; HttpOnly; SameSite=Strict; Path=/"]],
        url: "https://ex.test/",
      },
      ctx,
    )
    expect(r.issues.map((i) => i.code)).toContain("COOKIE_NO_SECURE")
  })

  it("passes clean cookie", async () => {
    const r = await cookieAudit(
      {
        headers: [["set-cookie", "sid=abc; Secure; HttpOnly; SameSite=Strict; Path=/"]],
        url: "https://ex.test/",
      },
      ctx,
    )
    expect(r.issues).toEqual([])
  })

  it("never stores cookie value", async () => {
    const r = await cookieAudit(
      {
        headers: [["set-cookie", "sid=SECRET123; Secure; HttpOnly; SameSite=Strict; Path=/"]],
        url: "https://ex.test/",
      },
      ctx,
    )
    expect(JSON.stringify(r.data)).not.toContain("SECRET123")
    expect(r.data?.cookies[0]?.value_length).toBe(9)
  })
})
