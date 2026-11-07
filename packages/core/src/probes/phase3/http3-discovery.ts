import { defineProbe } from "../../probe.js"
import type { Http3Discovery, HttpsSvcbRecord } from "../../types/index.js"

type H = Array<[string, string]>

export interface Http3DiscoveryInput {
  headers: H
  dns_https?: HttpsSvcbRecord[]
}

export const http3Discovery = defineProbe<Http3DiscoveryInput, Http3Discovery>(
  "http3Discovery",
  ["advertised"],
  async (input) => {
    const altSvc = input.headers.find(([k]) => k.toLowerCase() === "alt-svc")?.[1]
    const via_alt_svc = !!altSvc && /\bh3\b/.test(altSvc) && !/\bclear\b/.test(altSvc)
    const httpsAlpns = (input.dns_https ?? []).flatMap((r) => r.alpn ?? [])
    const via_https_record = httpsAlpns.includes("h3")
    return {
      status: "pass",
      data: {
        advertised: via_alt_svc || via_https_record,
        via_alt_svc,
        via_https_record,
        alt_svc_header: altSvc,
        https_record_alpn: httpsAlpns.length ? httpsAlpns : undefined,
      },
    }
  },
)
