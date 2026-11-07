// Top-level aggregates composing per-probe shapes into the full Trace JSON.
import type { AUDIT_ALGORITHM_VERSION, SCHEMA_VERSION } from "../version.js"
import type { RdapResult, DnsRecords, EmailStackResult } from "./phase1.js"
import type { DnsResolve, Http3Discovery, HttpExchange, TcpConnect, TlsHandshake } from "./phase2.js"
import type { CookieAudit, HeadersAudit, HostingFingerprint, SecurityTxtResult, SubresourceList } from "./phase3.js"
import type { Grade, Issue, ProbeResult, Timing } from "./primitives.js"

export interface DomainContext {
  domain: string
  rdap: ProbeResult<RdapResult>
  dns: ProbeResult<DnsRecords>
  email: ProbeResult<EmailStackResult>
}

export interface NetworkAttempt {
  stack: "v4" | "v6"
  server_address: string
  network_peer_address: string
  network_peer_port: number
  network_protocol_version: string
  timings: {
    dns: number | null
    connect: number | null
    ssl: number | null
    send: number | null
    wait: number | null
    receive: number | null
  }
  dns: ProbeResult<DnsResolve>
  tcp: ProbeResult<TcpConnect>
  tls: ProbeResult<TlsHandshake>
  http: ProbeResult<HttpExchange>
  quic?: ProbeResult<Http3Discovery>
  curl_command: string
}

export interface HttpResponse {
  protocol: "http/1.1" | "h2" | "h3"
  status: number
  headers: Array<[string, string]>
  body: HttpExchange["body"]
  ttfb_ms: number
  total_ms: number
}

export interface RequestTrace {
  url: string
  attempts: { v4?: NetworkAttempt; v6?: NetworkAttempt }
  primaryStack: "v4" | "v6" | "none"
  response?: HttpResponse
  audits: {
    headers: ProbeResult<HeadersAudit>
    cookies: ProbeResult<CookieAudit>
    subresources: ProbeResult<SubresourceList>
    hosting: ProbeResult<HostingFingerprint>
    securityTxt: ProbeResult<SecurityTxtResult>
    http3: ProbeResult<Http3Discovery>
  }
  redirectsTo?: string
  timing: Timing
}

export interface RunnerInfo {
  name: "poirot"
  version: string
  runtime: "node" | "bun"
  runtime_version: string
  hostname?: string
}

export interface Synthesis {
  verdict: "pass" | "warn" | "fail"
  grade: Grade
  score: number
  worst_issues: Issue[]
  timings: {
    total_ms: number
    by_phase: {
      hostname_context_ms: number
      network_ms: number
      audits_ms: number
      synthesis_ms: number
    }
    slowest_hop?: { url: string; duration_ms: number }
  }
  change_hash: string
  change_fields: string[]
  audit_algorithm_version: typeof AUDIT_ALGORITHM_VERSION
}

export interface Trace {
  schemaVersion: typeof SCHEMA_VERSION
  traceStartedAt: string
  duration_ms: number
  input: {
    raw: string
    url: string
    userAgent: string
    flags: Record<string, unknown>
  }
  runner: RunnerInfo
  domain: DomainContext
  requests: RequestTrace[]
  synthesis: Synthesis
}
