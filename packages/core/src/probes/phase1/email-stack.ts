import { bimi as mailauthBimi, dmarc as mailauthDmarc, spf as mailauthSpf } from "mailauth"
import { ISSUE } from "../../issues/codes.js"
import { dnsQuery } from "../../net/dns-packet.js"
import { defineProbe, untilAborted } from "../../probe.js"
import type { DnsRecords, EmailStackResult, Issue } from "../../types/index.js"
// MTA-STS helpers are NOT in mailauth's main export — import from the sub-module
// @ts-ignore - no types for this sub-module
import * as mtaSts from "mailauth/lib/mta-sts.js"

export interface EmailStackInput {
  domain: string
  dns: DnsRecords
  dkim_selectors: string[]
  /** Resolver for DKIM TXT lookups (IP or DoH URL). Default 1.1.1.1. */
  resolver?: string
}

async function resolveDkim(
  domain: string,
  selector: string,
  signal: AbortSignal,
  resolver: string,
): Promise<{ record?: string; valid: boolean; issues: Issue[] }> {
  const name = `${selector}._domainkey.${domain}`
  try {
    const pkt = await dnsQuery(name, "TXT", resolver, 3000, signal)
    const txt = (pkt.answers ?? []).find((answer: any) => answer.type === "TXT") as any
    if (!txt) return { valid: false, issues: [] }
    const record: string = Array.isArray(txt.data)
      ? (txt.data as Buffer[]).map((buffer) => buffer.toString()).join("")
      : String(txt.data)
    // Minimal v1 validation: must start with v=DKIM1 and include p= (public key).
    const valid = /\bv=DKIM1\b/i.test(record) && /\bp=[A-Za-z0-9+/=]+/.test(record)
    const issues: Issue[] = []
    if (!valid) {
      issues.push({
        severity: "warn",
        code: ISSUE.DKIM_MALFORMED,
        message: `Selector '${selector}' record missing v=DKIM1 or p= tag`,
      })
    }
    return { record, valid, issues }
  } catch {
    return { valid: false, issues: [] } // NXDOMAIN / timeout → selector simply not present
  }
}

export const emailStack = defineProbe<EmailStackInput, EmailStackResult>(
  "emailStack",
  ["spf.record", "dmarc.parsed.p", "dmarc.parsed.pct", "dkim", "bimi.svg_url", "mta_sts.policy.mode", "mta_sts.policy.mx", "null_mx"],
  async ({ domain, dns, dkim_selectors, resolver = "1.1.1.1" }, ctx) => {
    const issues: Issue[] = []
    const null_mx = dns.mx.length === 1 && dns.mx[0]?.host === "." && dns.mx[0]?.priority === 0
    if (null_mx) {
      issues.push({ severity: "info", code: ISSUE.EMAIL_NULL_MX, message: "Null MX (RFC 7505) — domain rejects mail" })
      return { status: "pass", data: { null_mx: true, dkim: {}, mx: dns.mx }, issues }
    }

    // SPF
    let spfRes: any = null
    try {
      spfRes = await untilAborted(mailauthSpf({ sender: `test@${domain}`, ip: "0.0.0.0", helo: domain, mta: "poirot" } as any), ctx.signal)
    } catch {
      // noop
    }
    if (spfRes?.rr) {
      const count: number = spfRes.lookups?.count ?? 0
      if (count > 10) {
        issues.push({ severity: "fail", code: ISSUE.SPF_LOOKUP_LIMIT_EXCEEDED, message: `SPF chain used ${count} DNS lookups (limit 10)` })
      } else if (count >= 8) {
        issues.push({ severity: "warn", code: ISSUE.SPF_LOOKUP_LIMIT_NEAR, message: `SPF chain used ${count} of 10 DNS lookups` })
      }
    } else {
      issues.push({ severity: "warn", code: ISSUE.SPF_MISSING, message: "No SPF record" })
    }

    // DMARC
    let dmarcRes: any = null
    try {
      dmarcRes = await untilAborted(mailauthDmarc({ headerFrom: domain } as any), ctx.signal)
    } catch {
      // noop
    }
    if (!dmarcRes?.policy) {
      issues.push({ severity: "warn", code: ISSUE.DMARC_MISSING, message: "No DMARC record" })
    } else if (dmarcRes.policy === "none") {
      issues.push({ severity: "warn", code: ISSUE.DMARC_POLICY_NONE, message: "DMARC p=none" })
    }

    // BIMI
    let bimiRes: any = null
    try {
      bimiRes = await untilAborted(mailauthBimi({ dmarc: dmarcRes, headers: { parsed: [{ key: "from", value: `a@${domain}` }] } } as any), ctx.signal)
    } catch {
      // noop
    }

    // MTA-STS
    let mtaStsRes: any = null
    try {
      mtaStsRes = await untilAborted((mtaSts as any).getPolicy(domain), ctx.signal)
    } catch {
      // noop
    }
    if (!mtaStsRes || mtaStsRes.status === "not_found") {
      issues.push({ severity: "warn", code: ISSUE.MTA_STS_MISSING, message: "No MTA-STS policy" })
    } else if (mtaStsRes.policy?.mode !== "enforce") {
      issues.push({ severity: "warn", code: ISSUE.MTA_STS_NOT_ENFORCED, message: `MTA-STS mode=${mtaStsRes.policy?.mode}` })
    }

    // DKIM — query every selector in parallel; keep only the ones that have a TXT record.
    const dkimEntries = await Promise.all(dkim_selectors.map(async (selector) => [selector, await resolveDkim(domain, selector, ctx.signal, resolver)] as const))

    // Cut off by the deadline: results are partial, so "missing" findings would be false.
    if (ctx.signal.aborted) {
      return {
        status: "warn",
        issues: [{ severity: "warn", code: ISSUE.DNS_TIMEOUT, message: "Email checks did not finish in time (SPF/DMARC/DKIM/BIMI/MTA-STS lookups)" }],
      }
    }
    const dkim: EmailStackResult["dkim"] = {}
    for (const [selector, result] of dkimEntries) {
      if (result.record || result.valid) dkim[selector] = { record: result.record, valid: result.valid, issues: result.issues }
      for (const issue of result.issues) issues.push(issue)
    }
    if (dkim_selectors.length > 0 && Object.keys(dkim).length === 0) {
      issues.push({
        severity: "warn",
        code: ISSUE.DKIM_NO_SELECTORS_FOUND,
        message: `No DKIM selectors found across ${dkim_selectors.length} tried`,
      })
    }

    const status = issues.some((issue) => issue.severity === "fail")
      ? "fail"
      : issues.some((issue) => issue.severity === "warn")
        ? "warn"
        : "pass"

    return {
      status,
      data: {
        null_mx: false,
        spf: spfRes?.rr ? { record: spfRes.rr, parsed: spfRes, validation: [], lookups: spfRes.lookups } : undefined,
        dmarc: dmarcRes?.policy ? { record: dmarcRes.record ?? "", parsed: dmarcRes, validation: [] } : undefined,
        dkim,
        bimi: bimiRes?.location
          ? {
              record: bimiRes.record ?? "",
              svg_url: bimiRes.location,
              dmarc_enforcement_ok: dmarcRes?.policy === "reject" || dmarcRes?.policy === "quarantine",
            }
          : undefined,
        mta_sts: mtaStsRes
          ? {
              dns_record: mtaStsRes.id ?? "",
              policy_fetched: mtaStsRes.status === "found",
              policy: mtaStsRes.policy,
              validation: [],
            }
          : undefined,
        mx: dns.mx,
      },
      issues,
    }
  },
)
