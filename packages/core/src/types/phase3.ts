// Phase 3 — audit shapes (headers, cookies, subresources, hosting, security.txt).
import type { Issue, ProbeStatus } from "./primitives.js"

export interface HeadersAudit {
  hsts: {
    value?: string
    max_age?: number
    include_subdomains?: boolean
    preload?: boolean
    preload_listed?: boolean
    status: ProbeStatus
  }
  csp: {
    value?: string
    directives?: Record<string, string[]>
    warnings?: string[]
    status: ProbeStatus
  }
  x_frame_options: { value?: string; status: ProbeStatus }
  x_content_type_options: { value?: string; status: ProbeStatus }
  referrer_policy: { value?: string; status: ProbeStatus }
  permissions_policy: { value?: string; status: ProbeStatus }
  coop: { value?: string; status: ProbeStatus }
  coep: { value?: string; status: ProbeStatus }
  corp: { value?: string; status: ProbeStatus }
  server_leak: { server?: string; x_powered_by?: string; status: ProbeStatus }
  early_hints_seen: boolean
}

export interface CookieAudit {
  cookies: ParsedCookie[]
}

export interface ParsedCookie {
  name: string
  value_length: number
  secure: boolean
  http_only: boolean
  same_site: "Strict" | "Lax" | "None" | "Unset"
  path?: string
  domain?: string
  max_age?: number
  expires?: string
  prefix: "__Host-" | "__Secure-" | null
  prefix_rules_respected: boolean
  issues: Issue[]
}

export interface SubresourceList {
  resources: Array<{
    tag: "script" | "link" | "img" | "iframe" | "source" | "video" | "audio"
    url: string
    origin: "same" | "cross"
    mixed_content: boolean
    rel?: string
    as?: string
    has_integrity: boolean
    integrity?: string
  }>
  counts_by_type: Record<string, number>
  mixed_content_count: number
  sri_missing_count: number
  parse_truncated: boolean
}

export interface HostingFingerprint {
  ip: string
  asn?: number
  asn_org?: string
  country?: string
  cloud_provider?: string
  cdn: { detected: boolean; name?: string }
  waf: { detected: boolean; name?: string }
  reverse_dns?: string
}

export interface SecurityTxtResult {
  present: boolean
  url?: string
  preferred_contact?: string
  fields?: {
    contact?: string[]
    expires?: string
    encryption?: string[]
    preferred_languages?: string
    canonical?: string[]
    policy?: string
    acknowledgments?: string
  }
  parse_warnings?: Issue[]
}
