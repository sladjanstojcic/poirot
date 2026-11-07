import type { Issue, Trace } from "@poirot/core"

const timing = { startedAt_ms: 0, duration_ms: 0 }
const ok = <T>(data: T, issues: Issue[] = []) => ({ status: "pass" as const, data, issues, timing, alertable_fields: [] })
const skipped = (reason = "upstream_failed") => ({ status: "skipped" as const, issues: [], timing, skipped: { reason }, alertable_fields: [] })
const warn = (code: string, message: string): Issue => ({ severity: "warn", code, message })

function attempt(stack: "v4" | "v6", ip: string, status = 200) {
  return {
    stack,
    server_address: "ex.test",
    network_peer_address: ip,
    network_peer_port: 443,
    network_protocol_version: "2",
    timings: { dns: 3.4, connect: 11.2, ssl: 43.7, send: null, wait: 90.1, receive: 15.6 },
    dns: { ...ok({ hostname: "ex.test", stack, resolver: "system", chosen_ip: ip, all_answers: [ip], query_ms: 3 }), timing: { startedAt_ms: 0, duration_ms: 3.4 } },
    tcp: { ...ok({ ip, port: 443, connected: true, connect_ms: 11.2 }), timing: { startedAt_ms: 3, duration_ms: 11.2 } },
    tls: {
      ...ok({
        protocol_name: "TLS",
        protocol_version: "1.3",
        cipher: "TLS_AES_256_GCM_SHA384",
        alpn: "h2",
        sni: "ex.test",
        handshake_ms: 43.7,
        resumed: false,
        cert_chain: [],
        cert_leaf: {
          subject: "CN=ex.test",
          issuer: "C=US O=Let's Encrypt CN=R11",
          san: ["ex.test", "www.ex.test"],
          not_before: 1_700_000_000,
          not_after: 1_900_000_000,
          days_to_expiry: 75,
          fingerprint_sha256: "1A:F6:27:C6:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:EF:FB",
          key_algorithm: "EC",
        },
        ocsp: { checked: false, source: "none" },
        kex: { type: "ECDH", name: "X25519", size: 253 },
      }),
      timing: { startedAt_ms: 14, duration_ms: 43.7 },
    },
    http: {
      ...ok({
        protocol: "h2",
        status,
        headers: [["server", "nginx"], ["content-type", "text/html"], ["x-extra", "1"]],
        body: { bytes_received: 1234, content_type: "text/html", encoding: "gzip" },
        ttfb_ms: 90.1,
        total_ms: 105.7,
        curl_command: `curl -2v "https://ex.test/"`,
      }),
      timing: { startedAt_ms: 58, duration_ms: 105.7 },
    },
    curl_command: `curl -2v "https://ex.test/"`,
  }
}

function headersAudit() {
  return ok({
    hsts: { status: "pass", value: "max-age=63072000" },
    csp: { status: "fail" },
    x_frame_options: { status: "pass", value: "DENY" },
    x_content_type_options: { status: "pass", value: "nosniff" },
    referrer_policy: { status: "warn" },
    permissions_policy: { status: "warn" },
    coop: { status: "warn" },
    coep: { status: "pass" },
    corp: { status: "pass" },
    server_leak: { status: "pass" },
    early_hints_seen: false,
  })
}

function audits() {
  return {
    headers: headersAudit(),
    cookies: ok({ cookies: [] }),
    subresources: ok({
      resources: [],
      counts_by_type: { script: 3, link: 1 },
      mixed_content_count: 0,
      sri_missing_count: 0,
      parse_truncated: false,
    }),
    hosting: ok({ ip: "1.2.3.4", asn: 13335, asn_org: "CLOUDFLARENET", cdn: { detected: true, name: "Cloudflare" }, waf: { detected: false } }),
    securityTxt: ok({ present: false }),
    http3: ok({ advertised: true, via_alt_svc: true, via_https_record: false }),
  }
}

function base(issues: Issue[]): Trace {
  return {
    schemaVersion: "1.0",
    traceStartedAt: "2026-11-07T00:00:00Z",
    duration_ms: 162.38,
    input: { raw: "ex.test", url: "https://ex.test/", userAgent: "poirot/0.1.0", flags: {} },
    runner: { name: "poirot", version: "0.1.0", runtime: "node", runtime_version: "v24.19.0" },
    domain: {
      domain: "ex.test",
      rdap: ok({ registrar: "Example Registrar", expires: 1_893_456_000, days_to_expiry: 800, created: 800_000_000 }),
      dns: ok({ resolver: "1.1.1.1", a: ["1.2.3.4"], aaaa: ["2001:db8::1"], mx: [], txt: [], ns: ["ns1.ex.test", "ns2.ex.test"], caa: [], dnssec: { signed: false } }),
      email: ok({ null_mx: true, mx: [], dkim: {}, spf: undefined, dmarc: undefined }, []),
    },
    requests: [],
    synthesis: {
      verdict: "warn",
      grade: "B",
      score: 85,
      worst_issues: issues.slice(0, 3),
      timings: { total_ms: 162.38, by_phase: { hostname_context_ms: 10.5, network_ms: 120.25, audits_ms: 20.1, synthesis_ms: 1.2 } },
      change_hash: "abcdef0123456789",
      change_fields: [],
      audit_algorithm_version: 2,
    },
  } as any
}

export const FIVE_WARNINGS: Issue[] = [
  warn("CSP_MISSING", "No Content-Security-Policy header"),
  warn("MTA_STS_MISSING", "No MTA-STS policy"),
  warn("SPF_MISSING", "No SPF record"),
  warn("DMARC_MISSING", "No DMARC record"),
  warn("COOP_MISSING", "No Cross-Origin-Opener-Policy header"),
]

/** One hop, both stacks succeed, five warn issues (in audits) and one info issue. */
export function successTrace(): Trace {
  const t = base(FIVE_WARNINGS)
  const a = audits() as any
  a.headers.issues = [...FIVE_WARNINGS, { severity: "info", code: "REFERRER_POLICY_MISSING", message: "No Referrer-Policy header" }]
  t.requests = [
    {
      url: "https://ex.test/",
      attempts: { v4: attempt("v4", "1.2.3.4"), v6: attempt("v6", "2001:db8::1") },
      primaryStack: "v4",
      response: attempt("v4", "1.2.3.4").http.data,
      audits: a,
      timing: { startedAt_ms: 10, duration_ms: 162.38 },
    } as any,
  ]
  return t
}

/** Two hops: 301 to https://www.ex.test/, then 200. */
export function redirectTrace(): Trace {
  const t = successTrace()
  const first = { ...t.requests[0]!, redirectsTo: "https://www.ex.test/", response: { ...attempt("v4", "1.2.3.4", 301).http.data } } as any
  const second = { ...t.requests[0]!, url: "https://www.ex.test/" } as any
  t.requests = [first, second]
  return t
}

/** Refused TCP on v4, no v6: no response, every audit skipped. */
export function refusedTrace(): Trace {
  const t = base([{ severity: "fail", code: "TCP_REFUSED", message: "connect ECONNREFUSED 127.0.0.1:1" }])
  const a = attempt("v4", "127.0.0.1") as any
  a.tcp = { status: "fail", issues: [{ severity: "fail", code: "TCP_REFUSED", message: "connect ECONNREFUSED 127.0.0.1:1" }], timing, alertable_fields: [] }
  a.tls = skipped()
  a.http = skipped()
  t.domain.rdap = skipped("not_applicable") as any
  t.domain.dns = skipped("not_applicable") as any
  t.domain.email = skipped("not_applicable") as any
  t.requests = [
    {
      url: "http://127.0.0.1:1/",
      attempts: { v4: a },
      primaryStack: "none",
      response: undefined,
      audits: { headers: skipped(), cookies: skipped(), subresources: skipped(), hosting: skipped(), securityTxt: skipped(), http3: skipped() },
      timing: { startedAt_ms: 0, duration_ms: 2.2 },
    } as any,
  ]
  t.synthesis = { ...t.synthesis, verdict: "fail", grade: "F", score: 0 }
  return t
}
