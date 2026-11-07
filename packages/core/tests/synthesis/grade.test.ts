import { describe, expect, it } from "vitest"
import { computeGrade } from "../../src/synthesis/grade.js"
import type { Issue } from "../../src/types/index.js"

function mkHeaders(hsts?: { max_age: number; include_subdomains: boolean }) {
  return { hsts: hsts ? { ...hsts, status: "pass" as const } : { status: "fail" as const } } as any
}

describe("computeGrade (Mozilla Observatory-aligned)", () => {
  it("A+ when base 100 + HSTS-preload bonus unlocks (strong HSTS)", () => {
    const issues: Issue[] = [{ severity: "info", code: "HSTS_PRELOAD_ELIGIBLE", message: "" }]
    const r = computeGrade(issues, mkHeaders({ max_age: 63072000, include_subdomains: true }))
    expect(r.grade).toBe("A+")
    expect(r.score).toBe(100)
  })

  it("bonuses rejected when base score is below 90 (Mozilla gate)", () => {
    const issues: Issue[] = [
      { severity: "warn", code: "CSP_MISSING", message: "" },
      { severity: "warn", code: "HSTS_MISSING", message: "" },
      { severity: "info", code: "HSTS_PRELOAD_ELIGIBLE", message: "" },
    ]
    const r = computeGrade(issues, mkHeaders({ max_age: 63072000, include_subdomains: true }))
    expect(r.score).toBe(55)
    expect(r.grade).toBe("F")
  })

  it("F when CERT_EXPIRED regardless of score", () => {
    const issues: Issue[] = [{ severity: "fail", code: "CERT_EXPIRED", message: "" }]
    const r = computeGrade(issues, mkHeaders())
    expect(r.grade).toBe("F")
  })

  it("B when one moderate fail (clickjacking -20)", () => {
    const issues: Issue[] = [{ severity: "warn", code: "CLICKJACKING_NOT_PREVENTED", message: "" }]
    const r = computeGrade(issues, mkHeaders())
    expect(r.score).toBe(80)
    expect(r.grade).toBe("B")
  })

  it("does not penalize unmapped warn codes", () => {
    const issues: Issue[] = [{ severity: "warn", code: "RDAP_UNREACHABLE", message: "" }]
    const r = computeGrade(issues, mkHeaders())
    expect(r.score).toBe(100)
    expect(r.grade).toBe("A")
  })

  it("de-dupes by code — the same code emitted twice counts exactly once", () => {
    const once: Issue[] = [{ severity: "warn", code: "HSTS_MISSING", message: "v4" }]
    const twice: Issue[] = [
      { severity: "warn", code: "HSTS_MISSING", message: "v4" },
      { severity: "warn", code: "HSTS_MISSING", message: "v6" },
    ]
    expect(computeGrade(twice).score).toBe(computeGrade(once).score)
    expect(computeGrade(twice).score).toBe(80)
  })
})
