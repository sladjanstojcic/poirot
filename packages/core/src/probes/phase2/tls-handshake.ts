import { X509Certificate } from "node:crypto"
import net from "node:net"
import { performance } from "node:perf_hooks"
import tls from "node:tls"
import { getCertStatus } from "easy-ocsp"
import { ISSUE } from "../../issues/codes.js"
import { defineProbe, untilAborted } from "../../probe.js"
import type { CertSummary, Issue, LeafCert, TlsHandshake } from "../../types/index.js"

export interface TlsHandshakeInput {
  hostname: string
  ip: string
  port: number
  timeout_ms?: number
}

// Versions below TLS 1.2 (spec phase2 §3.6: "Protocol version < 1.2 negotiated").
const LEGACY_TLS_VERSIONS = new Set(["SSLv3", "TLSv1", "TLSv1.1"])

function parseSan(san: string | undefined): string[] {
  if (!san) return []
  return san
    .split(", ")
    .map((item) => item.replace(/^DNS:/, "").replace(/^IP Address:/, ""))
    .filter(Boolean)
}

export const tlsHandshake = defineProbe<TlsHandshakeInput, TlsHandshake>(
  "tlsHandshake",
  ["cert_leaf.fingerprint_sha256", "cert_leaf.issuer", "cert_leaf.not_after", "cert_leaf.san", "protocol_version", "cipher", "alpn"],
  async ({ hostname, ip, port, timeout_ms = 6000 }, ctx) => {
    const t0 = performance.now()
    let sock: tls.TLSSocket
    try {
      sock = await handshake()
    } catch (error) {
      if ((error as Error).message !== "TLS_TIMEOUT") throw error
      return {
        status: "fail",
        issues: [{ severity: "fail", code: ISSUE.TLS_TIMEOUT, message: ctx.signal.aborted ? "deadline exceeded" : "TLS handshake timeout" }],
      }
    }

    function handshake(): Promise<tls.TLSSocket> {
      return new Promise<tls.TLSSocket>((ok, ko) => {
        const socket = tls.connect(
          {
            host: ip,
            port,
            // SNI must be a DNS name (RFC 6066); Node warns (DEP0123) when given an IP.
            ...(net.isIP(hostname) ? {} : { servername: hostname }),
            ALPNProtocols: ["h2", "http/1.1"],
            rejectUnauthorized: false,
          },
          () => {
            cleanup()
            ok(socket)
          },
        )
        socket.once("error", (error) => {
          cleanup()
          ko(error)
        })
        const fail = () => {
          cleanup()
          socket.destroy()
          ko(new Error("TLS_TIMEOUT"))
        }
        const timer = setTimeout(fail, timeout_ms)
        const cleanup = () => {
          clearTimeout(timer)
          ctx.signal.removeEventListener("abort", fail)
        }
        if (ctx.signal.aborted) return fail()
        ctx.signal.addEventListener("abort", fail, { once: true })
      })
    }
    const handshake_ms = +(performance.now() - t0).toFixed(1)

    const raw = sock.getPeerCertificate(true) as any
    if (!raw?.raw) {
      sock.destroy()
      return { status: "fail", issues: [{ severity: "fail", code: ISSUE.TLS_TIMEOUT, message: "No peer certificate received" }] }
    }

    const cipher = sock.getCipher()
    const alpn = sock.alpnProtocol || undefined
    const version = sock.getProtocol() // "TLSv1.3" etc.
    const authorized = sock.authorized
    const resumed = sock.isSessionReused()
    const eph = (sock as any).getEphemeralKeyInfo?.()
    const kex = {
      type: (eph?.type ?? "ECDH") as "ECDH" | "DH",
      name: eph?.name ?? "unknown",
      size: eph?.size ?? 0,
    }

    // Walk chain
    const chain: CertSummary[] = []
    let current: any = raw
    for (let depth = 0; current?.raw && depth < 8; depth++) {
      const cert = new X509Certificate(current.raw)
      chain.push({
        subject: cert.subject.replace(/\n/g, " "),
        issuer: cert.issuer.replace(/\n/g, " "),
        not_before: Math.floor(new Date(cert.validFrom).getTime() / 1000),
        not_after: Math.floor(new Date(cert.validTo).getTime() / 1000),
        fingerprint_sha256: cert.fingerprint256,
        serial_number: cert.serialNumber,
      })
      if (current === current.issuerCertificate || !current.issuerCertificate) break
      current = current.issuerCertificate
    }

    const leafX = new X509Certificate(raw.raw)
    const not_after = Math.floor(new Date(leafX.validTo).getTime() / 1000)
    const days_to_expiry = Math.floor((not_after * 1000 - Date.now()) / 86400000)

    sock.end()

    const issues: Issue[] = []
    let status: "pass" | "warn" | "fail" = "pass"
    if (version && LEGACY_TLS_VERSIONS.has(version)) {
      issues.push({ severity: "warn", code: ISSUE.TLS_WEAK_VERSION, message: `TLS ${version}` })
      status = "warn"
    }
    if (days_to_expiry < 0) {
      issues.push({ severity: "fail", code: ISSUE.CERT_EXPIRED, message: `Cert expired ${Math.abs(days_to_expiry)}d ago` })
      status = "fail"
    } else if (days_to_expiry < 7) {
      issues.push({ severity: "fail", code: ISSUE.CERT_EXPIRING_7D, message: `Cert expires in ${days_to_expiry}d` })
      status = "fail"
    } else if (days_to_expiry < 30) {
      issues.push({ severity: "warn", code: ISSUE.CERT_EXPIRING_30D, message: `Cert expires in ${days_to_expiry}d` })
      if (status === "pass") status = "warn"
    }
    // Recompute the name match ourselves (spec phase2 §3.6): Node skips the
    // identity check when the chain is already untrusted.
    const identityError = tls.checkServerIdentity(hostname, raw)
    if (identityError) {
      issues.push({ severity: "fail", code: ISSUE.CERT_NAME_MISMATCH, message: identityError.message })
      status = "fail"
    }
    if (!authorized && String(sock.authorizationError) !== "ERR_TLS_CERT_ALTNAME_INVALID") {
      issues.push({ severity: "warn", code: ISSUE.CERT_UNTRUSTED, message: `Chain not trusted: ${sock.authorizationError}` })
      if (status === "pass") status = "warn"
    }

    // OCSP
    let ocsp: TlsHandshake["ocsp"]
    try {
      // Check the certificate this handshake actually received. (getCertStatusByDomain
      // would open a second connection by hostname, possibly to a different IP.)
      const issuerRaw = raw.issuerCertificate && raw.issuerCertificate !== raw ? raw.issuerCertificate.raw : undefined
      const result = await untilAborted(getCertStatus(raw.raw, { timeout: 5000, ...(issuerRaw ? { ca: issuerRaw } : {}) }), ctx.signal)
      ocsp = { checked: true, status: result.status as any, source: "fetched", responder_url: result.ocspUrl }
      if (result.status === "revoked") {
        issues.push({ severity: "fail", code: ISSUE.OCSP_REVOKED, message: "Certificate revoked per OCSP" })
        status = "fail"
      }
    } catch (error: any) {
      ocsp = { checked: false, source: "none", error: String(error.message || "").slice(0, 100) }
    }

    const leaf: LeafCert = {
      subject: leafX.subject.replace(/\n/g, " "),
      issuer: leafX.issuer.replace(/\n/g, " "),
      san: parseSan(leafX.subjectAltName),
      not_before: Math.floor(new Date(leafX.validFrom).getTime() / 1000),
      not_after,
      days_to_expiry,
      fingerprint_sha256: leafX.fingerprint256,
      serial_number: leafX.serialNumber,
      key_algorithm: (leafX.publicKey as any)?.asymmetricKeyType?.toUpperCase() ?? "UNKNOWN",
      key_size: (leafX.publicKey as any)?.asymmetricKeyDetails?.modulusLength,
      curve: (leafX.publicKey as any)?.asymmetricKeyDetails?.namedCurve,
    }

    return {
      status,
      data: {
        protocol_name: "TLS",
        protocol_version: version === "TLSv1.3" ? "1.3" : "1.2",
        cipher: cipher.standardName ?? cipher.name,
        alpn,
        sni: hostname,
        handshake_ms,
        resumed,
        cert_chain: chain,
        cert_leaf: leaf,
        ocsp,
        kex,
      },
      issues,
    }
  },
)
