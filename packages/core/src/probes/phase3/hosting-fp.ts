import { detectCdn, detectWaf } from "../../data/cdn-rules.js"
import { ISSUE } from "../../issues/codes.js"
import { teamCymruAsn, teamCymruAsnOrg } from "../../net/team-cymru.js"
import { defineProbe } from "../../probe.js"
import type { HostingFingerprint, Issue } from "../../types/index.js"

type H = Array<[string, string]>

export interface HostingFpInput {
  ip: string
  headers: H
}

function isPrivate(ip: string): boolean {
  if (ip.includes(":")) return /^(fc|fd|fe80|::1)/i.test(ip)
  return /^(10|127|169\.254|192\.168)\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip)
}

export const hostingFp = defineProbe<HostingFpInput, HostingFingerprint>(
  "hostingFingerprint",
  ["asn", "asn_org", "cloud_provider", "cdn.name"],
  async (input, ctx) => {
    const issues: Issue[] = []
    const cdn = detectCdn(input.headers)
    const waf = detectWaf(input.headers)

    let asn: number | undefined
    let asn_org: string | undefined
    let country: string | undefined
    if (isPrivate(input.ip)) {
      issues.push({ severity: "info", code: ISSUE.HOSTING_PRIVATE_IP, message: `${input.ip} is private/reserved` })
    } else if (!input.ip.includes(":")) {
      const r = await teamCymruAsn(input.ip, ctx.signal)
      if (r) {
        asn = r.asn
        country = r.country
        asn_org = (await teamCymruAsnOrg(r.asn, ctx.signal)) ?? undefined
      }
    }

    if (!cdn.detected && asn === undefined) {
      issues.push({ severity: "info", code: ISSUE.HOSTING_UNKNOWN, message: `Could not fingerprint ${input.ip}` })
    }

    return {
      status: "pass",
      data: {
        ip: input.ip,
        asn,
        asn_org,
        country,
        cloud_provider: cdn.name?.toLowerCase(),
        cdn,
        waf,
      },
      issues,
    }
  },
)
