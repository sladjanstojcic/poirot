import { defineProbe } from "../../probe.js"
import { ISSUE } from "../../issues/codes.js"
import type { Issue, SecurityTxtResult } from "../../types/index.js"

export interface SecurityTxtInput {
  origin: string
  timeout_ms?: number
}

export function extractField(body: string, name: string): string | undefined {
  const re = new RegExp(`^${name}:\\s*(.+?)\\s*$`, "im")
  return re.exec(body)?.[1]
}

export const securityTxt = defineProbe<SecurityTxtInput, SecurityTxtResult>(
  "securityTxt",
  ["present", "preferred_contact", "fields.expires"],
  async ({ origin, timeout_ms = 5000 }, ctx) => {
    const url = `${origin.replace(/\/$/, "")}/.well-known/security.txt`
    const issues: Issue[] = []
    const normalizeContact = (value: string): { value: string; issue?: Issue } => {
      if (/^[a-z][a-z0-9+.-]*:/i.test(value)) return { value }
      if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
        return {
          value: `mailto:${value}`,
          issue: {
            severity: "warn",
            code: ISSUE.SECURITYTXT_CONTACT_NOT_URI,
            message: "security.txt Contact should use URI syntax (normalized to mailto:)",
          },
        }
      }
      return {
        value,
        issue: {
          severity: "warn",
          code: ISSUE.SECURITYTXT_CONTACT_NOT_URI,
          message: "security.txt Contact should use URI syntax",
        },
      }
    }
    try {
      // One signal for the request *and* the body read; also correct when the
      // probe deadline already fired (a late addEventListener never would be).
      const signal = AbortSignal.any([ctx.signal, AbortSignal.timeout(timeout_ms)])
      const res = await fetch(url, { signal, redirect: "follow" })
      if (!res.ok) {
        issues.push({ severity: "info", code: ISSUE.SECURITYTXT_MISSING, message: `${url} not present (${res.status})` })
        return { status: "pass", data: { present: false }, issues }
      }
      const text = await res.text()
      const fetchedUrl = res.url || url
      const fields: Record<string, string[]> = {}
      for (const line of text.split(/\r?\n/)) {
        if (line.startsWith("-----")) continue
        const m = /^([A-Za-z][A-Za-z-]*):\s*(.*)$/.exec(line.trim())
        if (!m) continue
        const key = m[1]!.toLowerCase()
        const value = m[2]!
        if (key === "contact") {
          const normalized = normalizeContact(value)
          ;(fields.contact ||= []).push(normalized.value)
          if (normalized.issue) issues.push(normalized.issue)
          continue
        }
        ;(fields[key] ||= []).push(value)
      }
      if (!fields.contact) issues.push({ severity: "warn", code: ISSUE.SECURITYTXT_NO_CONTACT, message: "security.txt lacks Contact field" })
      if (!fields.expires) issues.push({ severity: "warn", code: ISSUE.SECURITYTXT_NO_EXPIRES, message: "security.txt lacks Expires field" })
      if (fields.canonical?.length && !fields.canonical.includes(fetchedUrl)) {
        issues.push({ severity: "warn", code: ISSUE.SECURITYTXT_CANONICAL_MISMATCH, message: "security.txt Canonical does not list fetched URL" })
      }
      if (fields.expires) {
        const exp = new Date(fields.expires[0]!).getTime()
        if (Number.isFinite(exp) && exp < Date.now()) {
          issues.push({ severity: "warn", code: ISSUE.SECURITYTXT_EXPIRED, message: "security.txt Expires is in the past" })
        }
      }
      return {
        status: issues.some((i) => i.severity === "warn") ? "warn" : "pass",
        data: {
          present: true,
          url: fetchedUrl,
          preferred_contact: fields.contact?.[0],
          fields: {
            contact: fields.contact,
            expires: fields.expires?.[0],
            encryption: fields.encryption,
            preferred_languages: fields["preferred-languages"]?.[0],
            canonical: fields.canonical,
            policy: fields.policy?.[0],
            acknowledgments: fields.acknowledgments?.[0],
          },
        },
        issues,
      }
    } catch {
      issues.push({ severity: "info", code: ISSUE.SECURITYTXT_MISSING, message: `${url} fetch failed` })
      return { status: "pass", data: { present: false }, issues }
    }
  },
)
