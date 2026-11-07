import setCookieParser from "set-cookie-parser"
import { defineProbe } from "../../probe.js"
import { ISSUE } from "../../issues/codes.js"
import type { CookieAudit, Issue, ParsedCookie } from "../../types/index.js"

type H = Array<[string, string]>

export interface CookieAuditInput {
  headers: H
  url: string
}

function looksLikeSession(name: string): boolean {
  return /sess|auth|token|sid|login/i.test(name)
}

export const cookieAudit = defineProbe<CookieAuditInput, CookieAudit>(
  "cookieAudit",
  ["cookies"],
  async (input) => {
    const raw = input.headers.filter(([k]) => k.toLowerCase() === "set-cookie").map(([, v]) => v)
    const u = new URL(input.url)
    const parsed = setCookieParser.parse(raw, { decodeValues: false })
    const cookies: ParsedCookie[] = []
    const allIssues: Issue[] = []

    for (const c of parsed) {
      const prefix: ParsedCookie["prefix"] = c.name.startsWith("__Host-")
        ? "__Host-"
        : c.name.startsWith("__Secure-")
          ? "__Secure-"
          : null
      let prefix_rules_respected = true
      if (prefix === "__Secure-" && !c.secure) prefix_rules_respected = false
      if (prefix === "__Host-" && (!c.secure || c.path !== "/" || c.domain)) prefix_rules_respected = false

      const issues: Issue[] = []
      if (u.protocol === "https:" && !c.secure) {
        issues.push({ severity: "warn", code: ISSUE.COOKIE_NO_SECURE, message: `${c.name} missing Secure` })
      }
      if (!c.httpOnly && looksLikeSession(c.name)) {
        issues.push({ severity: "warn", code: ISSUE.COOKIE_NO_HTTPONLY, message: `${c.name} (session-like) missing HttpOnly` })
      }
      if (!c.sameSite) {
        issues.push({ severity: "warn", code: ISSUE.COOKIE_NO_SAMESITE, message: `${c.name} missing SameSite` })
      }
      if (c.sameSite === "None" && !c.secure) {
        issues.push({ severity: "fail", code: ISSUE.COOKIE_SAMESITE_NONE_NO_SECURE, message: `${c.name} SameSite=None requires Secure` })
      }
      if (!prefix_rules_respected) {
        issues.push({ severity: "fail", code: ISSUE.COOKIE_PREFIX_RULES_VIOLATED, message: `${c.name} prefix rules violated` })
      }
      if ((c.value ?? "").length > 4096) {
        issues.push({ severity: "warn", code: ISSUE.COOKIE_OVERSIZED, message: `${c.name} exceeds 4KB` })
      }

      allIssues.push(...issues)
      cookies.push({
        name: c.name,
        value_length: (c.value ?? "").length,
        secure: !!c.secure,
        http_only: !!c.httpOnly,
        same_site: (c.sameSite as ParsedCookie["same_site"]) ?? "Unset",
        path: c.path,
        domain: c.domain,
        max_age: c.maxAge,
        expires: c.expires?.toISOString(),
        prefix,
        prefix_rules_respected,
        issues,
      })
    }

    const status = allIssues.some((i) => i.severity === "fail") ? "fail" : allIssues.length ? "warn" : "pass"
    return { status, data: { cookies }, issues: allIssues }
  },
)
