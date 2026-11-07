import { describe, expect, it } from "vitest"
import { probe } from "../../src/index.js"

const LIVE = process.env.POIROT_LIVE === "1"

describe.runIf(LIVE)("live: example.com", () => {
  it(
    "returns pass/warn/fail with a populated trace",
    async () => {
      const t = await probe("https://example.com", { timeout: 20000 })
      expect(["pass", "warn", "fail"]).toContain(t.synthesis.verdict)
      expect(t.requests.length).toBeGreaterThanOrEqual(1)
      expect(t.requests[0]?.response?.status).toBeGreaterThanOrEqual(200)
    },
    30000,
  )
})
