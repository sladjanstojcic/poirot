import { describe, expect, it, vi } from "vitest"

// Phase 1 is slow (a dead record resolver); the request itself must not wait for it.
const order: string[] = []
vi.mock("../../src/orchestrator/phase1-runner.js", () => ({
  runPhase1: vi.fn(async (input: any) => {
    await new Promise((resolve) => setTimeout(resolve, 800))
    order.push("phase1 done")
    const skipped = { status: "skipped", issues: [], timing: { startedAt_ms: 0, duration_ms: 0 }, skipped: { reason: "not_applicable" }, alertable_fields: [] }
    return { domain: input.domain, rdap: skipped, dns: skipped, email: skipped }
  }),
}))
vi.mock("../../src/orchestrator/dual-stack.js", () => ({
  dualStack: vi.fn(async () => {
    order.push("network started")
    if (!respond.current) return { primary: "none", v4: undefined, v6: undefined }
    const http = { status: "pass", issues: [], data: { protocol: "http/1.1", status: 200, headers: [["content-type", "text/plain"]], body: { bytes_received: 2 }, ttfb_ms: 1, total_ms: 1 } }
    const skipped = { status: "skipped", issues: [], timing: { startedAt_ms: 0, duration_ms: 0 }, skipped: { reason: "not_applicable" }, alertable_fields: [] }
    const v4 = { stack: "v4", http, dns: skipped, tcp: skipped, tls: skipped, network_peer_address: "192.0.2.1", timings: {} }
    return { primary: "v4", v4, v6: undefined }
  }),
}))
const respond = { current: false }

import { probe } from "../../src/orchestrator/probe.js"

describe("probe() ordering", () => {
  it("starts the first request without waiting for phase 1", async () => {
    await probe("https://poirot-fixture.example/", { timeout: 5000 })
    expect(order).toEqual(["network started", "phase1 done"])
  })

  it("runs the first hop's audits without waiting for phase 1", async () => {
    order.length = 0
    respond.current = true
    await probe("https://poirot-fixture.example/", {
      timeout: 5000,
      onEvent: (event: any) => {
        if (event.type === "probe.end" && event.name === "headersAudit") order.push("headers audited")
      },
    })
    respond.current = false
    expect(order.indexOf("headers audited")).toBeLessThan(order.indexOf("phase1 done"))
  })
})
