import { performance } from "node:perf_hooks"
import { describe, expect, it } from "vitest"
import { defineProbe, type ProbeCtx } from "../src/probe.js"

function makeCtx(): ProbeCtx {
  return {
    traceStart: performance.now(),
    signal: new AbortController().signal,
    flags: {},
    cache: new Map(),
    logger: () => {},
  }
}

describe("defineProbe wrapper", () => {
  it("converts success into a ProbeResult with ok status", async () => {
    const probe = defineProbe<{ x: number }, { doubled: number }>(
      "doubler",
      ["doubled"],
      async (input) => ({ status: "pass", data: { doubled: input.x * 2 }, issues: [] }),
    )
    const r = await probe({ x: 21 }, makeCtx())
    expect(r.status).toBe("pass")
    expect(r.data).toEqual({ doubled: 42 })
    expect(r.issues).toEqual([])
    expect(r.alertable_fields).toEqual(["doubled"])
    expect(r.timing.duration_ms).toBeGreaterThanOrEqual(0)
  })

  it("catches thrown errors and emits PROBE_THREW issue", async () => {
    const probe = defineProbe<void, void>("bad", [], async () => {
      throw new Error("boom")
    })
    const r = await probe(undefined, makeCtx())
    expect(r.status).toBe("fail")
    expect(r.issues).toHaveLength(1)
    expect(r.issues[0]?.code).toBe("PROBE_THREW")
    expect(r.issues[0]?.message).toContain("boom")
  })

  it("preserves skipped results", async () => {
    const probe = defineProbe<void, void>(
      "skip-me",
      [],
      async () => ({ status: "skipped", skipped: { reason: "disabled_by_flag" } }),
    )
    const r = await probe(undefined, makeCtx())
    expect(r.status).toBe("skipped")
    expect(r.skipped?.reason).toBe("disabled_by_flag")
  })
})
