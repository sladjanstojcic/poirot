import { performance } from "node:perf_hooks"
import { describe, expect, it } from "vitest"
import { http3Discovery } from "../../../src/probes/phase3/http3-discovery.js"

const ctx = {
  traceStart: performance.now(),
  signal: new AbortController().signal,
  flags: {},
  cache: new Map(),
  logger: () => {},
}

describe("http3Discovery", () => {
  it("detects via Alt-Svc h3 token", async () => {
    const r = await http3Discovery({ headers: [["alt-svc", `h3=":443"; ma=86400`]] }, ctx)
    expect(r.data?.advertised).toBe(true)
    expect(r.data?.via_alt_svc).toBe(true)
  })

  it("not advertised when no signals", async () => {
    const r = await http3Discovery({ headers: [] }, ctx)
    expect(r.data?.advertised).toBe(false)
  })
})
