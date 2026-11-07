import { performance } from "node:perf_hooks"
import { describe, expect, it, vi } from "vitest"
import { securityTxt } from "../../../src/probes/phase3/security-txt.js"

const ctx = {
  traceStart: performance.now(),
  signal: new AbortController().signal,
  flags: {},
  cache: new Map(),
  logger: () => {},
}

describe("securityTxt", () => {
  it("reports missing when 404", async () => {
    const g = globalThis as any
    const prev = g.fetch
    g.fetch = vi.fn(async () => new Response("", { status: 404 }))
    try {
      const r = await securityTxt({ origin: "https://ex.test" }, ctx)
      expect(r.data?.present).toBe(false)
      expect(r.issues.map((i) => i.code)).toContain("SECURITYTXT_MISSING")
    } finally {
      g.fetch = prev
    }
  })

  it("parses Contact + Expires", async () => {
    const txt = "Contact: mailto:sec@ex.test\nExpires: 2030-01-01T00:00:00Z\nCanonical: https://ex.test/.well-known/security.txt\n"
    const g = globalThis as any
    const prev = g.fetch
    g.fetch = vi.fn(async () => new Response(txt, { status: 200 }))
    try {
      const r = await securityTxt({ origin: "https://ex.test" }, ctx)
      expect(r.data?.present).toBe(true)
      expect(r.data?.fields?.contact).toEqual(["mailto:sec@ex.test"])
      expect(r.data?.preferred_contact).toBe("mailto:sec@ex.test")
    } finally {
      g.fetch = prev
    }
  })

  it("normalizes bare email contact and warns", async () => {
    const txt = "Contact: sec@ex.test\nExpires: 2030-01-01T00:00:00Z\n"
    const g = globalThis as any
    const prev = g.fetch
    g.fetch = vi.fn(async () => new Response(txt, { status: 200 }))
    try {
      const r = await securityTxt({ origin: "https://ex.test" }, ctx)
      expect(r.data?.fields?.contact).toEqual(["mailto:sec@ex.test"])
      expect(r.issues.map((i) => i.code)).toContain("SECURITYTXT_CONTACT_NOT_URI")
    } finally {
      g.fetch = prev
    }
  })

  it("warns when Canonical does not list fetched URL", async () => {
    const txt = "Contact: mailto:sec@ex.test\nExpires: 2030-01-01T00:00:00Z\nCanonical: https://wrong.test/.well-known/security.txt\n"
    const g = globalThis as any
    const prev = g.fetch
    g.fetch = vi.fn(async () => new Response(txt, { status: 200 }))
    try {
      const r = await securityTxt({ origin: "https://ex.test" }, ctx)
      expect(r.issues.map((i) => i.code)).toContain("SECURITYTXT_CANONICAL_MISMATCH")
    } finally {
      g.fetch = prev
    }
  })
})
