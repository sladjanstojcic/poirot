import type { Grade, HeadersAudit, Issue } from "../types/index.js"

const PENALTIES: Record<string, number> = {
  CSP_MISSING: -25,
  CSP_UNSAFE_INLINE: -20,
  CSP_UNSAFE_EVAL: -10,
  HSTS_MISSING: -20,
  HSTS_VERY_WEAK_MAX_AGE: -20,
  HSTS_WEAK_MAX_AGE: -10,
  CLICKJACKING_NOT_PREVENTED: -20,
  X_CONTENT_TYPE_OPTIONS_MISSING: -5,
  COOKIE_NO_SECURE: -20,
  COOKIE_SAMESITE_NONE_NO_SECURE: -40,
  COOKIE_PREFIX_RULES_VIOLATED: -20,
  COOKIE_NO_HTTPONLY: -5,
  COOKIE_SECURE_ON_HTTP_HOP: -40,
  MIXED_CONTENT_FOUND: -20,
  SRI_MISSING_ON_CROSS_ORIGIN: -5,
  REDIRECT_HTTPS_TO_HTTP: -40,
  REDIRECT_LOOP: -20,
  CERT_UNTRUSTED: -25,
  CERT_NAME_MISMATCH: -25,
  CERT_EXPIRING_30D: -10,
  TLS_WEAK_VERSION: -30,
  TLS_WEAK_CIPHER: -15,
}

const HARD_F_CODES = new Set([
  "CERT_EXPIRED",
  "CERT_EXPIRING_7D",
  "CERT_UNTRUSTED",
  "CERT_NAME_MISMATCH",
  "OCSP_REVOKED",
  "TLS_WEAK_VERSION",
  "REDIRECT_HTTPS_TO_HTTP",
  "DNS_NXDOMAIN",
  "DOMAIN_EXPIRED",
])

function penalty(issue: Issue): number {
  if (issue.code in PENALTIES) return PENALTIES[issue.code]!
  return 0
}

export function computeGrade(issues: Issue[], headersAuditData?: HeadersAudit): { grade: Grade; score: number } {
  const uniqueByCode = new Map<string, Issue>()
  for (const issue of issues) {
    if (!uniqueByCode.has(issue.code)) uniqueByCode.set(issue.code, issue)
  }

  let baseScore = 100
  let hardF = false
  for (const issue of uniqueByCode.values()) {
    baseScore += penalty(issue)
    if (HARD_F_CODES.has(issue.code)) hardF = true
  }

  let score = baseScore
  if (baseScore >= 90) {
    let bonus = 0
    if (uniqueByCode.has("HSTS_PRELOAD_ELIGIBLE")) bonus += 5
    const hsts = headersAuditData?.hsts
    if (hsts && (hsts.max_age ?? 0) >= 31536000 && hsts.include_subdomains) bonus += 2
    score = Math.min(107, baseScore + Math.min(7, bonus))
  }

  if (hardF && score > 55) score = 55
  const internalScore = Math.max(0, Math.min(107, score))
  const externalScore = Math.min(100, internalScore)

  const grade: Grade =
    internalScore > 100
      ? "A+"
      : externalScore >= 90
        ? "A"
        : externalScore >= 80
          ? "B"
          : externalScore >= 70
            ? "C"
            : externalScore >= 60
              ? "D"
              : "F"

  return { grade, score: externalScore }
}
