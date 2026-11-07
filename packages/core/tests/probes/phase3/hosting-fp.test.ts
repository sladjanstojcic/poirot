import { performance } from "node:perf_hooks"
import { describe, expect, it } from "vitest"
import { hostingFp } from "../../../src/probes/phase3/hosting-fp.js"

const ctx = {
  traceStart: performance.now(),
  signal: new AbortController().signal,
  flags: {},
  cache: new Map(),
  logger: () => {},
}

describe("hostingFingerprint", () => {
  it("detects Cloudflare via headers", async () => {
    const r = await hostingFp({ ip: "1.2.3.4", headers: [["cf-ray", "abc"], ["server", "cloudflare"]] }, ctx)
    expect(r.data?.cdn.detected).toBe(true)
    expect(r.data?.cdn.name).toBe("Cloudflare")
  })

  it("falls through to HOSTING_UNKNOWN when no signals", async () => {
    const r = await hostingFp({ ip: "10.0.0.1", headers: [] }, ctx)
    expect(r.issues.map((i) => i.code)).toContain("HOSTING_UNKNOWN")
  })
})
