import { describe, expect, it, vi } from "vitest"

// v4 answers fast; v6 hangs (blackholed network) until its signal aborts.
vi.mock("../../src/orchestrator/run-stack.js", () => ({
  runStack: vi.fn(async (args: any) => {
    if (args.stack === "v4") return { stack: "v4", http: { data: { status: 200 } }, tcp: { issues: [] }, tls: { issues: [] } }
    await new Promise<void>((resolve) => args.ctx.signal.addEventListener("abort", () => resolve()))
    return {
      stack: "v6",
      http: { status: "skipped", issues: [] },
      tcp: { status: "fail", issues: [{ severity: "fail", code: "TCP_ERROR", message: "aborted" }] },
      tls: { issues: [] },
    }
  }),
}))

import { dualStack } from "../../src/orchestrator/dual-stack.js"

describe("dualStack grace period", () => {
  it("does not wait for a hanging stack once the other answered", async () => {
    const t0 = Date.now()
    const r = await dualStack({ url: "https://h.test/", opts: { timeout: 30_000 } })
    expect(Date.now() - t0).toBeLessThan(3500)
    expect(r.primary).toBe("v4")
    expect(r.v6?.tcp.issues[0]?.code).toBe("TCP_ERROR")
  }, 10_000)
})
