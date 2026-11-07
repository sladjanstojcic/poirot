import fc from "fast-check"
import { describe, expect, it } from "vitest"
import { computeGrade } from "../../src/synthesis/grade.js"
import type { Issue } from "../../src/types/index.js"

const issueArb = fc.record({
  severity: fc.constantFrom<Issue["severity"]>("info", "warn", "fail"),
  code: fc.constantFrom(
    "CSP_MISSING",
    "HSTS_MISSING",
    "CLICKJACKING_NOT_PREVENTED",
    "X_CONTENT_TYPE_OPTIONS_MISSING",
    "COOKIE_NO_SECURE",
    "CERT_EXPIRING_30D",
    "TLS_WEAK_CIPHER",
    "HSTS_PRELOAD_ELIGIBLE",
  ),
  message: fc.string({ maxLength: 64 }),
})

const failIssueArb = fc.record({
  severity: fc.constant<Issue["severity"]>("fail"),
  code: fc.constantFrom("CSP_MISSING", "HSTS_VERY_WEAK_MAX_AGE", "CERT_EXPIRED", "REDIRECT_HTTPS_TO_HTTP"),
  message: fc.string({ maxLength: 64 }),
})

describe("computeGrade properties", () => {
  it("adding a fail-severity issue never improves score", () => {
    fc.assert(
      fc.property(fc.array(issueArb, { maxLength: 20 }), failIssueArb, (existing, extra) => {
        const before = computeGrade(existing).score
        const after = computeGrade([...existing, extra]).score
        expect(after).toBeLessThanOrEqual(before)
      }),
      { numRuns: 300 },
    )
  })

  it("score stays in [0, 100] and grade stays in allowed set", () => {
    fc.assert(
      fc.property(fc.array(issueArb, { maxLength: 30 }), (issues) => {
        const { grade, score } = computeGrade(issues)
        expect(score).toBeGreaterThanOrEqual(0)
        expect(score).toBeLessThanOrEqual(100)
        expect(["A+", "A", "B", "C", "D", "F"]).toContain(grade)
      }),
      { numRuns: 300 },
    )
  })

  it("adding duplicate-code issue does not change score", () => {
    fc.assert(
      fc.property(fc.array(issueArb, { minLength: 1, maxLength: 10 }), fc.integer({ min: 0, max: 9 }), (existing, pickRaw) => {
        const idx = pickRaw % existing.length
        const dup = { ...existing[idx]!, message: "duplicate emission" }
        const before = computeGrade(existing).score
        const after = computeGrade([...existing, dup]).score
        expect(after).toBe(before)
      }),
      { numRuns: 200 },
    )
  })

  it("unmapped warn codes do not affect score", () => {
    fc.assert(
      fc.property(fc.constantFrom("RDAP_UNREACHABLE", "RDAP_MALFORMED", "HOSTING_UNKNOWN", "SECURITYTXT_MISSING"), (code) => {
        const { score } = computeGrade([{ severity: "warn", code, message: "lookup noise" }])
        expect(score).toBe(100)
      }),
      { numRuns: 100 },
    )
  })
})
