// Phase 2 — per-origin network shapes: DNS→TCP→TLS→HTTP for one IP family.

export interface DnsResolve {
  hostname: string
  stack: "v4" | "v6"
  resolver: string
  chosen_ip: string
  all_answers: string[]
  ttl?: number
  cname_chain?: string[]
  query_ms: number
}

export interface TcpConnect {
  ip: string
  port: number
  connected: boolean
  connect_ms: number
  rtt_estimate_ms?: number
  local_address?: string
}

export interface TlsHandshake {
  protocol_name: "TLS"
  protocol_version: "1.2" | "1.3"
  cipher: string
  alpn?: string
  sni: string
  handshake_ms: number
  resumed: boolean
  cert_chain: CertSummary[]
  cert_leaf: LeafCert
  ocsp: OcspResult
  kex: KexInfo
}

export interface CertSummary {
  subject: string
  issuer: string
  not_before: number
  not_after: number
  fingerprint_sha256: string
  serial_number?: string
}

export interface LeafCert extends CertSummary {
  san: string[]
  days_to_expiry: number
  key_algorithm: string
  key_size?: number
  curve?: string
}

export interface OcspResult {
  checked: boolean
  status?: "good" | "revoked" | "unknown"
  source: "stapled" | "fetched" | "none"
  responder_url?: string
  checked_ms?: number
  error?: string
}

export interface KexInfo {
  type: "ECDH" | "DH"
  name: string
  size: number
}

export interface HttpExchange {
  protocol: "http/1.1" | "h2" | "h3"
  status: number
  headers: Array<[string, string]>
  body: {
    bytes_received: number
    truncated_at?: number
    content_type?: string
    encoding?: string
    sha256?: string
  }
  ttfb_ms: number
  total_ms: number
  curl_command: string
}

export interface Http3Discovery {
  advertised: boolean
  via_alt_svc: boolean
  via_https_record: boolean
  alt_svc_header?: string
  https_record_alpn?: string[]
}
