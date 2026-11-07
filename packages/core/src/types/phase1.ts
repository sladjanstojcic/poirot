// Phase 1 — hostname context probes' data shapes.
import type { Issue, ProbeResult } from "./primitives.js"

export interface RdapResult {
  registrar?: string
  created?: number
  updated?: number
  expires?: number
  age_days?: number
  days_to_expiry?: number
  nameservers?: string[]
  statuses?: string[]
  entities_raw?: unknown
  bootstrap_url?: string
}

export interface DnsRecords {
  resolver: string
  a: string[]
  aaaa: string[]
  cname?: string
  mx: { host: string; priority: number }[]
  txt: string[]
  ns: string[]
  caa: { flag: number; tag: string; value: string }[]
  soa?: {
    mname: string
    rname: string
    serial: number
    refresh: number
    retry: number
    expire: number
    minimum: number
  }
  https?: HttpsSvcbRecord[]
  dnssec: {
    signed: boolean
    rrsig_present: boolean
    ds_present_at_parent: boolean
    dnskey_present: boolean
    algorithm?: string
  }
  queries_made: number
  total_ms: number
}

export interface HttpsSvcbRecord {
  priority: number
  target: string
  alpn?: string[]
  port?: number
  ipv4hint?: string[]
  ipv6hint?: string[]
  ech?: string
}

export interface EmailStackResult {
  null_mx: boolean
  spf?: {
    record: string
    parsed: unknown
    validation: Issue[]
    lookups?: { limit: number; count: number; void: number }
  }
  dmarc?: { record: string; parsed: unknown; validation: Issue[] }
  dkim: Record<string, { record?: string; valid: boolean; issues: Issue[] }>
  bimi?: {
    record: string
    svg_url?: string
    svg_reachable?: boolean
    dmarc_enforcement_ok: boolean
  }
  mta_sts?: {
    dns_record: string
    policy_fetched: boolean
    policy?: MtaStsPolicy
    validation: Issue[]
  }
  mx: { host: string; priority: number; smtp_probe?: ProbeResult<SmtpProbeResult> }[]
}

export interface MtaStsPolicy {
  version: "STSv1"
  mode: "enforce" | "testing" | "none"
  mx: string[]
  max_age: number
}

export interface SmtpProbeResult {
  reachable: boolean
  hosts: Array<{
    host: string
    priority: number
    connected: boolean
    greeting?: string
    supports_starttls?: boolean
    starttls_succeeded?: boolean
    error?: string
  }>
}
