import { performance } from "node:perf_hooks"
import { describe, expect, it } from "vitest"
import { smtpProbe } from "../../../src/probes/phase2/smtp-probe.js"

describe("smtpProbe", () => {
  it("skips when --probe-smtp flag is not set", async () => {
    const ctx = {
      traceStart: performance.now(),
      signal: new AbortController().signal,
      flags: {},
      cache: new Map(),
      logger: () => {},
    }
    const r = await smtpProbe({ mx: [{ host: "mx.example.com", priority: 10 }] }, ctx)
    expect(r.status).toBe("skipped")
    expect(r.skipped?.reason).toBe("disabled_by_flag")
  })

  it("runs when probe_smtp flag is true", async () => {
    const ctx = {
      traceStart: performance.now(),
      signal: new AbortController().signal,
      flags: { probe_smtp: true },
      cache: new Map(),
      logger: () => {},
    }
    const r = await smtpProbe({ mx: [{ host: "127.0.0.1", priority: 10 }] }, ctx)
    // Should return a result (probably unreachable in CI) — key assertion: flag check worked
    expect(["pass", "warn", "fail"]).toContain(r.status)
  })
})
