import { describe, expect, it } from "vitest"
import { computeTimings } from "../../src/synthesis/timings.js"

describe("computeTimings", () => {
  it("rolls up per-phase with slowest hop", () => {
    const trace: any = {
      duration_ms: 500,
      domain: {
        rdap: { timing: { duration_ms: 80 } },
        dns: { timing: { duration_ms: 30 } },
        email: { timing: { duration_ms: 20 } },
      },
      requests: [
        {
          url: "https://ex.test/a",
          timing: { duration_ms: 300 },
          attempts: { v4: { http: { timing: { duration_ms: 200 } } } },
          audits: {
            headers: { timing: { duration_ms: 10 } },
            cookies: { timing: { duration_ms: 5 } },
            subresources: { timing: { duration_ms: 8 } },
            hosting: { timing: { duration_ms: 20 } },
            securityTxt: { timing: { duration_ms: 15 } },
            http3: { timing: { duration_ms: 1 } },
          },
        },
      ],
    }
    const r = computeTimings(trace)
    expect(r.total_ms).toBe(500)
    expect(r.by_phase.hostname_context_ms).toBeGreaterThan(0)
    expect(r.slowest_hop?.url).toBe("https://ex.test/a")
  })
})
