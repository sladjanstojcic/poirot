import { performance } from "node:perf_hooks"
import { describe, expect, it, vi } from "vitest"

// Stub the HSTS preload API so tests don't hit hstspreload.org on every run.
vi.mock("../../../src/probes/phase3/hsts-preload.js", () => ({
  hstsPreloadStatus: vi.fn(async () => "preloaded" as const),
}))

import { headersAudit } from "../../../src/probes/phase3/headers-audit.js"

const ctx = {
  traceStart: performance.now(),
  signal: new AbortController().signal,
  flags: {},
  cache: new Map(),
  logger: () => {},
}

describe("headersAudit", () => {
  it("pass with modern header set", async () => {
    const r = await headersAudit(
      {
        headers: [
          ["strict-transport-security", "max-age=63072000; includeSubDomains; preload"],
          ["content-security-policy", "default-src 'self'; base-uri 'self'; form-action 'self'"],
          ["x-content-type-options", "nosniff"],
          ["x-frame-options", "DENY"],
          ["referrer-policy", "no-referrer"],
        ],
        url: "https://ex.test/",
      },
      ctx,
    )
    expect(r.data?.hsts.status).toBe("pass")
    expect(r.data?.hsts.preload_listed).toBe(true)
    expect(r.issues.map((issue) => issue.code)).toContain("HSTS_PRELOAD_ELIGIBLE")
  })

  it("warn when CSP missing", async () => {
    const r = await headersAudit({ headers: [["x-frame-options", "DENY"]], url: "https://ex.test/" }, ctx)
    expect(r.issues.map((issue) => issue.code)).toContain("CSP_MISSING")
  })

  it("warns when CSP omits base-uri and form-action", async () => {
    const r = await headersAudit(
      {
        headers: [
          ["content-security-policy", "default-src 'self'"],
          ["x-frame-options", "DENY"],
        ],
        url: "https://ex.test/",
      },
      ctx,
    )
    expect(r.issues.map((issue) => issue.code)).toContain("CSP_BASE_URI_MISSING")
    expect(r.issues.map((issue) => issue.code)).toContain("CSP_FORM_ACTION_MISSING")
  })
})
