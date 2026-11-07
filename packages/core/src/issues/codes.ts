type Severity = "info" | "warn" | "fail"
/**
 * Canonical taxonomy of every issue code Poirot emits.
 * `emitted_at` declares the probe/module that raises the code. The invariant
 * test in Step 1 asserts every entry has ≥ 1 site, so codes never go dead.
 */
interface CodeMeta {
  severity: Severity
  message: string
  emitted_at: string[] // paths relative to packages/core/src (no extensions)
  doc?: string
}

export const ISSUE_CODES = {
  // Universal
  PROBE_THREW: {
    severity: "fail",
    message: "A probe threw an unexpected error.",
    emitted_at: ["probe"],
  }, // emitted by the defineProbe() wrapper

  // DNS / domain
  DNS_TIMEOUT: {
    severity: "fail",
    message: "DNS resolver did not respond.",
    emitted_at: ["probes/phase1/dns-records", "probes/phase2/dns-resolve"],
  },
  DNS_SERVFAIL: {
    severity: "fail",
    message: "DNS resolver returned SERVFAIL.",
    emitted_at: ["probes/phase1/dns-records", "probes/phase2/dns-resolve"],
  },
  DNS_NXDOMAIN: {
    severity: "fail",
    message: "Domain does not exist (NXDOMAIN).",
    emitted_at: ["probes/phase1/dns-records", "probes/phase2/dns-resolve"],
  },
  DNS_UNREACHABLE: {
    severity: "fail",
    message: "DNS resolver unreachable.",
    emitted_at: ["probes/phase1/dns-records", "probes/phase2/dns-resolve"],
  },
  DOMAIN_NO_ADDRESS: {
    severity: "fail",
    message: "Domain has no A or AAAA records.",
    emitted_at: ["probes/phase1/dns-records"],
  },
  DOMAIN_UNREGISTERED: {
    severity: "warn",
    message: "Domain appears unregistered (RDAP 404).",
    emitted_at: ["probes/phase1/rdap"],
  },
  DOMAIN_EXPIRED: {
    severity: "warn",
    message: "Domain registration has expired.",
    emitted_at: ["probes/phase1/rdap"],
  },
  DOMAIN_EXPIRING_30D: {
    severity: "warn",
    message: "Domain expires within 30 days.",
    emitted_at: ["probes/phase1/rdap"],
  },
  DOMAIN_EXPIRING_7D: {
    severity: "fail",
    message: "Domain expires within 7 days.",
    emitted_at: ["probes/phase1/rdap"],
  },
  RDAP_NO_SERVER: {
    severity: "warn",
    message: "No RDAP server for this TLD and fallback failed.",
    emitted_at: ["probes/phase1/rdap"],
  },
  RDAP_UNREACHABLE: {
    severity: "warn",
    message: "RDAP server unreachable.",
    emitted_at: ["probes/phase1/rdap"],
  },
  RDAP_MALFORMED: {
    severity: "warn",
    message: "RDAP response did not match RFC 9083 shape.",
    emitted_at: ["probes/phase1/rdap"],
  },
  CAA_MISMATCH: {
    severity: "warn",
    message: "Cert issuer not in CAA allow-list.",
    emitted_at: ["synthesis/caa-cross-check"],
  },
  CAA_ISSUER_UNRECOGNIZED: {
    severity: "info",
    message: "Cert issuer not in ca-mapping; cannot cross-check CAA.",
    emitted_at: ["synthesis/caa-cross-check"],
  },
  CAA_FORBIDS_ISSUANCE: {
    severity: "fail",
    message: "CAA explicitly forbids issuance but a cert is deployed.",
    emitted_at: ["synthesis/caa-cross-check"],
  },
  DNSSEC_UNSIGNED_ANSWER: {
    severity: "warn",
    message: "DNSKEY present but RRSIG not observed on answer.",
    emitted_at: ["probes/phase1/dns-records"],
  },
  SVCB_MALFORMED: {
    severity: "warn",
    message: "HTTPS/SVCB record failed to parse.",
    emitted_at: ["probes/phase1/dns-records"],
  },

  // Email
  EMAIL_NULL_MX: {
    severity: "info",
    message: "Null MX (RFC 7505) — domain does not accept email.",
    emitted_at: ["probes/phase1/email-stack"],
  },
  SPF_MISSING: {
    severity: "warn",
    message: "No SPF record.",
    emitted_at: ["probes/phase1/email-stack"],
  },
  SPF_MULTIPLE: {
    severity: "fail",
    message: "Multiple SPF records (RFC 7208 forbids).",
    emitted_at: ["probes/phase1/email-stack"],
  },
  SPF_PERMISSIVE: {
    severity: "warn",
    message: "SPF ends with +all or ?all (permissive).",
    emitted_at: ["probes/phase1/email-stack"],
  },
  SPF_LOOKUP_LIMIT_NEAR: {
    severity: "warn",
    message: "SPF chain consumed ≥ 8 of 10 DNS lookups.",
    emitted_at: ["probes/phase1/email-stack"],
  },
  SPF_LOOKUP_LIMIT_EXCEEDED: {
    severity: "fail",
    message: "SPF chain exceeded 10 DNS lookups (invalid).",
    emitted_at: ["probes/phase1/email-stack"],
  },
  DMARC_MISSING: {
    severity: "warn",
    message: "No DMARC record.",
    emitted_at: ["probes/phase1/email-stack"],
  },
  DMARC_POLICY_NONE: {
    severity: "warn",
    message: "DMARC p=none (monitoring only).",
    emitted_at: ["probes/phase1/email-stack"],
  },
  DMARC_NO_REPORTING: {
    severity: "info",
    message: "DMARC record has no rua (aggregate reporting).",
    emitted_at: ["probes/phase1/email-stack"],
  },
  DKIM_NO_SELECTORS_FOUND: {
    severity: "warn",
    message: "No DKIM selectors found across tried set.",
    emitted_at: ["probes/phase1/email-stack"],
  },
  DKIM_MALFORMED: {
    severity: "warn",
    message: "DKIM record malformed.",
    emitted_at: ["probes/phase1/email-stack"],
  },
  BIMI_DMARC_NOT_ENFORCED: {
    severity: "warn",
    message: "BIMI present but DMARC not enforced.",
    emitted_at: ["probes/phase1/email-stack"],
  },
  BIMI_SVG_UNREACHABLE: {
    severity: "warn",
    message: "BIMI SVG URL unreachable.",
    emitted_at: ["probes/phase1/email-stack"],
  },
  MTA_STS_MISSING: {
    severity: "warn",
    message: "No MTA-STS policy published.",
    emitted_at: ["probes/phase1/email-stack"],
  },
  MTA_STS_POLICY_MISSING: {
    severity: "warn",
    message: "MTA-STS DNS TXT present but policy file not fetched.",
    emitted_at: ["probes/phase1/email-stack"],
  },
  MTA_STS_NOT_ENFORCED: {
    severity: "warn",
    message: "MTA-STS mode is not 'enforce'.",
    emitted_at: ["probes/phase1/email-stack"],
  },

  // Dual-stack
  DUALSTACK_V4_MISSING: {
    severity: "info",
    message: "No A record (IPv4).",
    emitted_at: ["synthesis/verdict"],
  },
  DUALSTACK_V6_MISSING: {
    severity: "info",
    message: "No AAAA record (IPv6).",
    emitted_at: ["synthesis/verdict"],
  },
  DUALSTACK_PARTIAL: {
    severity: "warn",
    message: "Only one IP family produced a response.",
    emitted_at: ["synthesis/verdict"],
  },
  DUALSTACK_CERT_DIVERGENT: {
    severity: "warn",
    message: "Cert fingerprints differ between v4 and v6.",
    emitted_at: ["synthesis/verdict"],
  },
  DUALSTACK_STATUS_DIVERGENT: {
    severity: "warn",
    message: "HTTP status differs between v4 and v6.",
    emitted_at: ["synthesis/verdict"],
  },

  // TCP
  TCP_REFUSED: {
    severity: "fail",
    message: "Connection refused.",
    emitted_at: ["probes/phase2/tcp-connect"],
  },
  TCP_UNREACHABLE: {
    severity: "fail",
    message: "Network unreachable.",
    emitted_at: ["probes/phase2/tcp-connect"],
  },
  TCP_TIMEOUT: {
    severity: "fail",
    message: "TCP connect timed out.",
    emitted_at: ["probes/phase2/tcp-connect"],
  },
  TCP_ERROR: {
    severity: "fail",
    message: "TCP error.",
    emitted_at: ["probes/phase2/tcp-connect"],
  },
  IPV6_NON_GLOBAL: {
    severity: "info",
    message: "IPv6 address is link-local or ULA; skipped.",
    emitted_at: ["probes/phase2/dns-resolve"],
  },

  // TLS
  TLS_TIMEOUT: {
    severity: "fail",
    message: "TLS handshake timed out.",
    emitted_at: ["probes/phase2/tls-handshake"],
  },
  TLS_WEAK_VERSION: {
    severity: "warn",
    message: "TLS version below 1.2 negotiated.",
    emitted_at: ["probes/phase2/tls-handshake"],
  },
  TLS_WEAK_CIPHER: {
    severity: "warn",
    message: "Weak cipher (export/RC4/3DES) negotiated.",
    emitted_at: ["probes/phase2/tls-handshake"],
  },
  TLS_WEAK_KEY: {
    severity: "warn",
    message: "Weak key (RSA < 2048 / old EC curve).",
    emitted_at: ["probes/phase2/tls-handshake"],
  },
  TLS_CLIENT_CERT_REQUIRED: {
    severity: "fail",
    message: "Server requires mTLS; not supported in v1.",
    emitted_at: ["probes/phase2/tls-handshake"],
  },
  CERT_UNTRUSTED: {
    severity: "warn",
    message: "Certificate chain not trusted by Node's root store.",
    emitted_at: ["probes/phase2/tls-handshake"],
  },
  CERT_EXPIRED: {
    severity: "fail",
    message: "Certificate has expired.",
    emitted_at: ["probes/phase2/tls-handshake"],
  },
  CERT_EXPIRING_30D: {
    severity: "warn",
    message: "Certificate expires within 30 days.",
    emitted_at: ["probes/phase2/tls-handshake"],
  },
  CERT_EXPIRING_7D: {
    severity: "fail",
    message: "Certificate expires within 7 days.",
    emitted_at: ["probes/phase2/tls-handshake"],
  },
  CERT_NAME_MISMATCH: {
    severity: "fail",
    message: "Certificate does not cover this hostname.",
    emitted_at: ["probes/phase2/tls-handshake"],
  },
  OCSP_REVOKED: {
    severity: "fail",
    message: "Certificate is revoked (OCSP).",
    emitted_at: ["probes/phase2/tls-handshake"],
  },
  OCSP_UNKNOWN: {
    severity: "warn",
    message: "OCSP status unknown or fetch failed.",
    emitted_at: ["probes/phase2/tls-handshake"],
  },

  // HTTP
  HTTP_TIMEOUT: {
    severity: "fail",
    message: "HTTP request timed out.",
    emitted_at: ["probes/phase2/http-exchange"],
  },
  HTTP_RESET: {
    severity: "fail",
    message: "Connection reset mid-response.",
    emitted_at: ["probes/phase2/http-exchange"],
  },
  HTTP_MALFORMED: {
    severity: "fail",
    message: "Invalid chunked encoding or malformed response.",
    emitted_at: ["probes/phase2/http-exchange"],
  },
  HTTP_NO_CONTENT_LENGTH: {
    severity: "warn",
    message: "No Content-Length and no proper EOF.",
    emitted_at: ["probes/phase2/http-exchange"],
  },
  HTTP_BODY_TRUNCATED: {
    severity: "info",
    message: "Response body exceeded body cap; truncated.",
    emitted_at: ["probes/phase2/http-exchange"],
  },
  HTTP_UNKNOWN_ENCODING: {
    severity: "warn",
    message: "Unrecognized content-encoding.",
    emitted_at: ["probes/phase2/http-exchange"],
  },
  HTTP_RATE_LIMITED: {
    severity: "info",
    message: "Server returned 429 Too Many Requests (Retry-After honored for subsequent probes).",
    emitted_at: ["probes/phase2/http-exchange"],
  },

  // Redirects
  REDIRECT_LOOP: {
    severity: "fail",
    message: "Redirect loop detected.",
    emitted_at: ["orchestrator/redirect-follow"],
  },
  REDIRECT_MAX_HOPS: {
    severity: "warn",
    message: "Redirect chain hit max hop count.",
    emitted_at: ["orchestrator/redirect-follow"],
  },
  REDIRECT_CROSS_ORIGIN: {
    severity: "info",
    message: "Redirect crosses to a different eTLD+1.",
    emitted_at: ["orchestrator/redirect-follow"],
  },
  REDIRECT_HTTPS_TO_HTTP: {
    severity: "fail",
    message: "Redirect downgrades https → http.",
    emitted_at: ["orchestrator/redirect-follow"],
  },

  // Headers
  HSTS_MISSING: {
    severity: "warn",
    message: "No Strict-Transport-Security header.",
    emitted_at: ["probes/phase3/headers-audit"],
  },
  HSTS_WEAK_MAX_AGE: {
    severity: "warn",
    message: "HSTS max-age below 1 year.",
    emitted_at: ["probes/phase3/headers-audit"],
  },
  HSTS_VERY_WEAK_MAX_AGE: {
    severity: "fail",
    message: "HSTS max-age below 30 days.",
    emitted_at: ["probes/phase3/headers-audit"],
  },
  HSTS_MULTIPLE: {
    severity: "info",
    message: "Multiple HSTS headers.",
    emitted_at: ["probes/phase3/headers-audit"],
  },
  HSTS_PRELOAD_ELIGIBLE: {
    severity: "info",
    message: "Domain is in the Chromium HSTS preload list.",
    emitted_at: ["probes/phase3/hsts-preload"],
  },
  HSTS_PRELOAD_MISSING: {
    severity: "info",
    message: "preload directive present but domain not in Chromium list.",
    emitted_at: ["probes/phase3/hsts-preload"],
  },
  CSP_MISSING: {
    severity: "warn",
    message: "No Content-Security-Policy header.",
    emitted_at: ["probes/phase3/headers-audit"],
  },
  CSP_UNSAFE_INLINE: {
    severity: "warn",
    message: "CSP contains 'unsafe-inline'.",
    emitted_at: ["probes/phase3/headers-audit"],
  },
  CSP_UNSAFE_EVAL: {
    severity: "warn",
    message: "CSP contains 'unsafe-eval'.",
    emitted_at: ["probes/phase3/headers-audit"],
  },
  CSP_BASE_URI_MISSING: {
    severity: "warn",
    message: "CSP lacks base-uri directive.",
    emitted_at: ["probes/phase3/headers-audit"],
  },
  CSP_FORM_ACTION_MISSING: {
    severity: "warn",
    message: "CSP lacks form-action directive.",
    emitted_at: ["probes/phase3/headers-audit"],
  },
  CLICKJACKING_NOT_PREVENTED: {
    severity: "warn",
    message: "No X-Frame-Options nor CSP frame-ancestors.",
    emitted_at: ["probes/phase3/headers-audit"],
  },
  X_CONTENT_TYPE_OPTIONS_MISSING: {
    severity: "warn",
    message: "Missing X-Content-Type-Options: nosniff.",
    emitted_at: ["probes/phase3/headers-audit"],
  },
  REFERRER_POLICY_MISSING: {
    severity: "info",
    message: "No Referrer-Policy header.",
    emitted_at: ["probes/phase3/headers-audit"],
  },
  REFERRER_POLICY_UNSAFE_URL: {
    severity: "warn",
    message: "Referrer-Policy is unsafe-url.",
    emitted_at: ["probes/phase3/headers-audit"],
  },
  PERMISSIONS_POLICY_MISSING: {
    severity: "info",
    message: "No Permissions-Policy header.",
    emitted_at: ["probes/phase3/headers-audit"],
  },
  ISOLATION_HEADERS_MISSING: {
    severity: "info",
    message: "COOP/COEP/CORP not set.",
    emitted_at: ["probes/phase3/headers-audit"],
  },
  SERVER_VERSION_LEAK: {
    severity: "info",
    message: "Server header leaks version.",
    emitted_at: ["probes/phase3/headers-audit"],
  },
  X_POWERED_BY_LEAK: {
    severity: "info",
    message: "X-Powered-By header present.",
    emitted_at: ["probes/phase3/headers-audit"],
  },

  // Subresources
  MIXED_CONTENT_FOUND: {
    severity: "warn",
    message: "Mixed-content subresources detected.",
    emitted_at: ["probes/phase3/subresource"],
  },
  SUBRESOURCE_BODY_TRUNCATED: {
    severity: "info",
    message: "HTML body was truncated; subresource count may be under-reported.",
    emitted_at: ["probes/phase3/subresource"],
  },
  SRI_MISSING_ON_CROSS_ORIGIN: {
    severity: "warn",
    message: "Cross-origin script/stylesheet without Subresource Integrity.",
    emitted_at: ["probes/phase3/subresource"],
  },

  // Cookies
  COOKIE_NO_SECURE: {
    severity: "warn",
    message: "Cookie set on https without Secure.",
    emitted_at: ["probes/phase3/cookie-audit"],
  },
  COOKIE_NO_HTTPONLY: {
    severity: "warn",
    message: "Session-like cookie without HttpOnly.",
    emitted_at: ["probes/phase3/cookie-audit"],
  },
  COOKIE_NO_SAMESITE: {
    severity: "warn",
    message: "Cookie missing SameSite.",
    emitted_at: ["probes/phase3/cookie-audit"],
  },
  COOKIE_SAMESITE_NONE_NO_SECURE: {
    severity: "fail",
    message: "SameSite=None requires Secure.",
    emitted_at: ["probes/phase3/cookie-audit"],
  },
  COOKIE_PREFIX_RULES_VIOLATED: {
    severity: "fail",
    message: "__Host-/__Secure- prefix rules violated.",
    emitted_at: ["probes/phase3/cookie-audit"],
  },
  COOKIE_OVERSIZED: {
    severity: "warn",
    message: "Cookie exceeds 4 KB.",
    emitted_at: ["probes/phase3/cookie-audit"],
  },
  COOKIE_SECURE_ON_HTTP_HOP: {
    severity: "fail",
    message: "Secure cookie set on plain-HTTP redirect hop.",
    emitted_at: ["synthesis/cookie-hop-check"],
  },

  // Hosting
  HOSTING_UNKNOWN: {
    severity: "info",
    message: "Could not fingerprint hosting for IP.",
    emitted_at: ["probes/phase3/hosting-fp"],
  },
  HOSTING_PRIVATE_IP: {
    severity: "info",
    message: "IP is private/reserved.",
    emitted_at: ["probes/phase3/hosting-fp"],
  },

  // security.txt
  SECURITYTXT_MISSING: {
    severity: "info",
    message: "/.well-known/security.txt not present.",
    emitted_at: ["probes/phase3/security-txt"],
  },
  SECURITYTXT_NO_CONTACT: {
    severity: "warn",
    message: "security.txt lacks Contact field.",
    emitted_at: ["probes/phase3/security-txt"],
  },
  SECURITYTXT_CONTACT_NOT_URI: {
    severity: "warn",
    message: "security.txt Contact should use URI syntax.",
    emitted_at: ["probes/phase3/security-txt"],
  },
  SECURITYTXT_NO_EXPIRES: {
    severity: "warn",
    message: "security.txt lacks Expires field.",
    emitted_at: ["probes/phase3/security-txt"],
  },
  SECURITYTXT_CANONICAL_MISMATCH: {
    severity: "warn",
    message: "security.txt Canonical does not list fetched URL.",
    emitted_at: ["probes/phase3/security-txt"],
  },
  SECURITYTXT_EXPIRED: {
    severity: "warn",
    message: "security.txt Expires is in the past.",
    emitted_at: ["probes/phase3/security-txt"],
  },

  // SMTP
  SMTP_UNREACHABLE: {
    severity: "warn",
    message: "All MX hosts failed to connect on port 25.",
    emitted_at: ["probes/phase2/smtp-probe"],
  },
  SMTP_NO_STARTTLS: {
    severity: "warn",
    message: "MX does not advertise STARTTLS.",
    emitted_at: ["probes/phase2/smtp-probe"],
  },
  SMTP_STARTTLS_FAILED: {
    severity: "warn",
    message: "STARTTLS advertised but upgrade failed.",
    emitted_at: ["probes/phase2/smtp-probe"],
  },
} as const satisfies Record<string, CodeMeta>

export type IssueCode = keyof typeof ISSUE_CODES

export const ISSUE = Object.freeze(
  Object.fromEntries(Object.keys(ISSUE_CODES).map((key) => [key, key])) as {
    [K in IssueCode]: K
  },
)
