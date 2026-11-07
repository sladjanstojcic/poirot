import { cookieAudit } from "../probes/phase3/cookie-audit.js"
import { headersAudit } from "../probes/phase3/headers-audit.js"
import { hostingFp } from "../probes/phase3/hosting-fp.js"
import { http3Discovery } from "../probes/phase3/http3-discovery.js"
import { securityTxt } from "../probes/phase3/security-txt.js"
import { subresource } from "../probes/phase3/subresource.js"
import type { ProbeCtx } from "../probe.js"
import type {
  CookieAudit,
  HeadersAudit,
  HostingFingerprint,
  Http3Discovery,
  HttpResponse,
  HttpsSvcbRecord,
  ProbeResult,
  SecurityTxtResult,
  SubresourceList,
} from "../types/index.js"

export interface Phase3Input {
  url: string
  origin: string
  response?: HttpResponse
  rawBody: Buffer
  peerIp: string
  dnsHttpsRecords?: HttpsSvcbRecord[]
}

export interface Phase3Audits {
  headers: ProbeResult<HeadersAudit>
  cookies: ProbeResult<CookieAudit>
  subresources: ProbeResult<SubresourceList>
  hosting: ProbeResult<HostingFingerprint>
  securityTxt: ProbeResult<SecurityTxtResult>
  http3: ProbeResult<Http3Discovery>
}

function upstreamFailed<T>(): ProbeResult<T> {
  return {
    status: "skipped",
    issues: [],
    timing: { startedAt_ms: 0, duration_ms: 0 },
    skipped: { reason: "upstream_failed" },
    alertable_fields: [],
  }
}

export async function runPhase3(input: Phase3Input, ctx: ProbeCtx): Promise<Phase3Audits> {
  // Audits describe a response. Without one, "missing header" findings would be
  // false, and security.txt would only re-probe a host that already failed.
  if (!input.response) {
    return {
      headers: upstreamFailed(),
      cookies: upstreamFailed(),
      subresources: upstreamFailed(),
      hosting: upstreamFailed(),
      securityTxt: upstreamFailed(),
      http3: upstreamFailed(),
    }
  }
  const headers = input.response?.headers ?? []
  const [headersResult, cookiesResult, subresourcesResult, hostingResult, securityTxtResult, http3Result] =
    await Promise.all([
      headersAudit({ headers, url: input.url }, ctx),
      cookieAudit({ headers, url: input.url }, ctx),
      subresource(
        {
          body: input.rawBody,
          body_truncated: !!input.response?.body.truncated_at,
          base_url: input.url,
          content_type: input.response?.body.content_type,
        },
        ctx,
      ),
      hostingFp({ ip: input.peerIp, headers }, ctx),
      securityTxt({ origin: input.origin }, ctx),
      http3Discovery({ headers, dns_https: input.dnsHttpsRecords }, ctx),
    ])

  return {
    headers: headersResult,
    cookies: cookiesResult,
    subresources: subresourcesResult,
    hosting: hostingResult,
    securityTxt: securityTxtResult,
    http3: http3Result,
  }
}
