import { describe, expect, it } from "vitest"
import { ISSUE_CODES, type IssueCode } from "../../src/issues/codes.js"

describe("ISSUE_CODES registry", () => {
  it("has PROBE_THREW (every probe may emit this)", () => {
    expect(ISSUE_CODES.PROBE_THREW).toBeDefined()
    expect(ISSUE_CODES.PROBE_THREW.severity).toBe("fail")
  })

  it("has v1.1 additions", () => {
    const added: IssueCode[] = [
      "CAA_MISMATCH",
      "CAA_ISSUER_UNRECOGNIZED",
      "CAA_FORBIDS_ISSUANCE",
      "SPF_LOOKUP_LIMIT_NEAR",
      "SPF_LOOKUP_LIMIT_EXCEEDED",
      "HSTS_PRELOAD_ELIGIBLE",
      "HSTS_PRELOAD_MISSING",
      "CSP_BASE_URI_MISSING",
      "CSP_FORM_ACTION_MISSING",
      "REFERRER_POLICY_UNSAFE_URL",
      "COOKIE_SECURE_ON_HTTP_HOP",
      "SRI_MISSING_ON_CROSS_ORIGIN",
      "SECURITYTXT_CONTACT_NOT_URI",
      "SECURITYTXT_CANONICAL_MISMATCH",
    ]
    for (const c of added) {
      expect(ISSUE_CODES[c]).toBeDefined()
    }
  })

  it("every entry has severity + message", () => {
    for (const [code, meta] of Object.entries(ISSUE_CODES)) {
      expect(["info", "warn", "fail"]).toContain(meta.severity)
      expect(typeof meta.message).toBe("string")
      expect(meta.message.length).toBeGreaterThan(0)
    }
  })

  it("every entry declares at least one emit site (no dead codes)", () => {
    for (const [code, meta] of Object.entries(ISSUE_CODES)) {
      expect(Array.isArray(meta.emitted_at), `${code} missing emitted_at[]`).toBe(true)
      expect((meta as any).emitted_at.length, `${code} has no emit site`).toBeGreaterThan(0)
    }
  })
})
