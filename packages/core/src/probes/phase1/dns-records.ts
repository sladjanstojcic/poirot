import { performance } from "node:perf_hooks"
import { ISSUE } from "../../issues/codes.js"
import { dnsQuery } from "../../net/dns-packet.js"
import { defineProbe } from "../../probe.js"
import type { DnsRecords, Issue } from "../../types/index.js"

const TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "CAA", "SOA", "HTTPS"] as const

function dnsIssue(code: string, recordType: string, detail: string): Issue {
  const messages: Record<string, string> = {
    [ISSUE.DNS_TIMEOUT]: `DNS ${recordType} query timed out`,
    [ISSUE.DNS_UNREACHABLE]: `DNS ${recordType} query failed`,
    [ISSUE.DNS_SERVFAIL]: `DNS ${recordType} query returned SERVFAIL`,
    [ISSUE.DNS_NXDOMAIN]: `DNS ${recordType} query returned NXDOMAIN`,
  }
  return { severity: "fail", code, message: detail ? `${messages[code] ?? "DNS query failed"}: ${detail}` : (messages[code] ?? "DNS query failed") }
}

function issueFromError(recordType: string, error: unknown): Issue {
  const err = error as NodeJS.ErrnoException
  const detail = err?.message ?? String(error)
  const code = err?.code ?? detail
  if (/DNS_TIMEOUT|ABORTED|ETIMEOUT|timeout/i.test(String(code)) || /DNS_TIMEOUT|ABORTED|timeout/i.test(detail)) {
    return dnsIssue(ISSUE.DNS_TIMEOUT, recordType, detail)
  }
  if (/SERVFAIL/i.test(String(code)) || /SERVFAIL/i.test(detail)) return dnsIssue(ISSUE.DNS_SERVFAIL, recordType, detail)
  if (/NXDOMAIN|ENOTFOUND/i.test(String(code)) || /NXDOMAIN|ENOTFOUND/i.test(detail)) {
    return dnsIssue(ISSUE.DNS_NXDOMAIN, recordType, detail)
  }
  return dnsIssue(ISSUE.DNS_UNREACHABLE, recordType, detail)
}

function issueFromRcode(recordType: string, rcode?: string): Issue | undefined {
  if (rcode === "SERVFAIL") return dnsIssue(ISSUE.DNS_SERVFAIL, recordType, rcode)
  if (rcode === "NXDOMAIN") return dnsIssue(ISSUE.DNS_NXDOMAIN, recordType, rcode)
  return undefined
}

function isRetryableAddressIssue(issue?: Issue): boolean {
  return issue?.code === ISSUE.DNS_TIMEOUT || issue?.code === ISSUE.DNS_UNREACHABLE
}

export const dnsRecords = defineProbe<{ domain: string; resolver?: string }, DnsRecords>(
  "dnsRecords",
  ["a", "aaaa", "mx", "ns", "caa", "dnssec.signed"],
  async ({ domain, resolver = "1.1.1.1" }, ctx) => {
    const t0 = performance.now()
    const queryRecord = async (recordType: (typeof TYPES)[number]) => {
      try {
        const pkt = await dnsQuery(domain, recordType as any, resolver, 3000, ctx.signal)
        return { recordType, pkt, issue: issueFromRcode(recordType, (pkt as any).rcode) }
      } catch (error) {
        return { recordType, pkt: null, issue: issueFromError(recordType, error) }
      }
    }
    const results = await Promise.all(TYPES.map(queryRecord))
    let queries_made = TYPES.length
    // Every query failed in transport: the resolver is unusable (blocked port 53,
    // dead DoH endpoint). Retrying and the DNSKEY query would only add 3 s each.
    const resolverDead = results.every((result) => isRetryableAddressIssue(result.issue))
    for (const recordType of resolverDead ? [] : (["A", "AAAA"] as const)) {
      const index = results.findIndex((result) => result.recordType === recordType)
      const result = results[index]
      if (result && !ctx.signal.aborted && isRetryableAddressIssue(result.issue)) {
        results[index] = await queryRecord(recordType)
        queries_made++
      }
    }

    const get = (recordType: string) =>
      (results.find((result) => result.recordType === recordType)?.pkt?.answers?.filter((answer: any) => answer.type === recordType) ??
        []) as any[]

    const a = get("A").map((answer: any) => answer.data as string)
    const aaaa = get("AAAA").map((answer: any) => answer.data as string)
    const cname = get("CNAME")[0]?.data as string | undefined
    const mx = get("MX").map((answer: any) => ({
      host: String(answer.data.exchange).toLowerCase(),
      priority: answer.data.preference as number,
    }))
    const ns = get("NS").map((answer: any) => String(answer.data).toLowerCase())
    const caa = get("CAA").map((answer: any) => ({
      flag: answer.data.flags as number,
      tag: answer.data.tag as string,
      value: answer.data.value as string,
    }))
    const txt = get("TXT").map((answer: any) =>
      Array.isArray(answer.data)
        ? (answer.data as Buffer[]).map((buffer) => buffer.toString()).join("")
        : String(answer.data),
    )

    const soaAnswer = get("SOA")[0]?.data as any
    const soa = soaAnswer
      ? {
          mname: soaAnswer.mname,
          rname: soaAnswer.rname,
          serial: soaAnswer.serial,
          refresh: soaAnswer.refresh,
          retry: soaAnswer.retry,
          expire: soaAnswer.expire,
          minimum: soaAnswer.minimum,
        }
      : undefined

    const https = get("HTTPS").map((answer: any) => {
      const data = answer.data as any
      return {
        priority: data.priority,
        target: data.target,
        alpn: data.values?.alpn,
        port: data.values?.port,
        ipv4hint: data.values?.ipv4hint,
        ipv6hint: data.values?.ipv6hint,
        ech: data.values?.ech,
      }
    })

    // DNSSEC detection — look for RRSIG/DNSKEY in DNSKEY response
    let rrsig_present = false
    let dnskey_present = false
    try {
      if (resolverDead) throw new Error("resolver unusable")
      const pkt = await dnsQuery(domain, "DNSKEY" as any, resolver, 3000, ctx.signal)
      queries_made++
      rrsig_present = (pkt.answers ?? []).some((answer: any) => answer.type === "RRSIG")
      dnskey_present = (pkt.answers ?? []).some((answer: any) => answer.type === "DNSKEY")
    } catch {
      // noop
    }

    const issues: Issue[] = []
    let status: "pass" | "warn" | "fail" = "pass"
    const addIssue = (issue: Issue) => {
      if (!issues.some((existing) => existing.code === issue.code)) issues.push(issue)
    }
    const addressResults = results.filter((result) => result.recordType === "A" || result.recordType === "AAAA")
    const addressIssues = addressResults.map((result) => result.issue).filter((issue): issue is Issue => Boolean(issue))
    for (const issue of addressIssues) addIssue(issue)
    if (addressIssues.length === 0 && a.length === 0 && aaaa.length === 0) {
      issues.push({ severity: "fail", code: ISSUE.DOMAIN_NO_ADDRESS, message: `No A or AAAA records for ${domain}` })
      status = "fail"
    }
    if (dnskey_present && !rrsig_present) {
      issues.push({ severity: "warn", code: ISSUE.DNSSEC_UNSIGNED_ANSWER, message: "DNSKEY present but no RRSIG observed" })
      if (status === "pass") status = "warn"
    }
    if (issues.some((issue) => issue.severity === "fail")) status = "fail"

    return {
      status,
      data: {
        resolver,
        a,
        aaaa,
        cname,
        mx,
        txt,
        ns,
        caa,
        soa,
        https: https.length ? https : undefined,
        dnssec: { signed: rrsig_present, rrsig_present, ds_present_at_parent: false, dnskey_present },
        queries_made,
        total_ms: Math.round(performance.now() - t0),
      },
      issues,
    }
  },
)
