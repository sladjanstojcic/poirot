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
    return { primary: "none", v4: undefined, v6: undefined }
  }),
}))

import { probe } from "../../src/orchestrator/probe.js"

describe("probe() ordering", () => {
  it("starts the first request without waiting for phase 1", async () => {
    await probe("https://poirot-fixture.example/", { timeout: 5000 })
    expect(order).toEqual(["network started", "phase1 done"])
  })
})
