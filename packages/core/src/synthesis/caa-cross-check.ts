import caMapping from "../data/ca-mapping.json" with { type: "json" }
import type { Issue } from "../types/index.js"

export function normOrg(value: string): string {
  return String(value || "")
    .toLowerCase()
    .replace(/["']/g, "")
    .replace(/,?\s*(inc|llc|ltd|gmbh|sa|sl)\.?\s*$/i, "")
    .replace(/[.,\\]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
}

export function extractOrg(issuerDN: string): string {
  const parts = (issuerDN || "").split(/[\n,]+/).map((part) => part.trim())
  const org = parts.find((part) => /^O\s*=/i.test(part))
  return org ? normOrg(org.replace(/^O\s*=\s*/i, "")) : ""
}

export function caaCrossCheck(
  caa: Array<{ flag: number; tag: string; value: string }>,
  certIssuerDN: string,
): Issue | null {
  const allow = new Set<string>()
  let hasCaaIssueTag = false
  for (const entry of caa) {
    if (entry.tag !== "issue" && entry.tag !== "issuewild") continue
    hasCaaIssueTag = true
    const raw = entry.value.trim()
    if (raw === ";" || raw === "") continue
    const ca = raw.split(";")[0]!.trim().toLowerCase()
    if (ca) allow.add(ca)
  }

  if (hasCaaIssueTag && allow.size === 0) {
    return {
      severity: "fail",
      code: "CAA_FORBIDS_ISSUANCE",
      message: "CAA forbids any CA but a cert is deployed",
    }
  }
  if (allow.size === 0) return null

  const certOrg = extractOrg(certIssuerDN)
  if (!certOrg) {
    return {
      severity: "info",
      code: "CAA_ISSUER_UNRECOGNIZED",
      message: "Couldn't extract O= from cert issuer DN",
    }
  }

  const allowedOrgs = new Set<string>()
  for (const domain of allow) {
    for (const candidate of ((caMapping as Record<string, string[]>)[domain] ?? [domain])) {
      allowedOrgs.add(normOrg(candidate))
    }
  }

  for (const allowedOrg of allowedOrgs) {
    if (certOrg.includes(allowedOrg) || allowedOrg.includes(certOrg)) return null
  }

  let knownCa = false
  for (const values of Object.values(caMapping as Record<string, string[]>)) {
    for (const value of values) {
      if (certOrg.includes(normOrg(value))) {
        knownCa = true
        break
      }
    }
    if (knownCa) break
  }

  return knownCa
    ? {
        severity: "warn",
        code: "CAA_MISMATCH",
        message: `Cert issuer "${certOrg}" not in CAA allow-list ${[...allow].join(", ")}`,
      }
    : {
        severity: "info",
        code: "CAA_ISSUER_UNRECOGNIZED",
        message: `Unknown cert issuer "${certOrg}"`,
      }
}
