import { describe, expect, it } from "vitest"
import { probe } from "../../src/index.js"
import { collectAllIssues } from "../../src/synthesis/verdict.js"

const LIVE = process.env.POIROT_LIVE === "1"

describe.runIf(LIVE)("live: badssl.com family", () => {
  it(
    "expired.badssl.com emits CERT_EXPIRED",
    async () => {
      const t = await probe("https://expired.badssl.com", { timeout: 20000 })
      const codes = collectAllIssues(t).map((i) => i.code)
      expect(codes).toContain("CERT_EXPIRED")
    },
    30000,
  )

  it(
    "self-signed.badssl.com emits CERT_UNTRUSTED",
    async () => {
      const t = await probe("https://self-signed.badssl.com", { timeout: 20000 })
      const codes = collectAllIssues(t).map((i) => i.code)
      expect(codes).toContain("CERT_UNTRUSTED")
    },
    30000,
  )
})
