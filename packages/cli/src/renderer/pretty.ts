import { STATUS_CODES } from "node:http"
import type { HeadersAudit, Issue, NetworkAttempt, ProbeResult, ProbeStatus, RequestTrace, Trace } from "@poirot/core"
import pc from "picocolors"
import { collectIssues } from "../issues.js"

// Layout follows spec 05 §6.2–6.4. Every ms value is rounded; every skipped
// phase says why instead of looking like a failure.

export interface RenderOpts {
  verbose: boolean
}

const LABEL = 14
/** Tree continuation line, aligned with the stage detail column. */
const CONTINUATION = `    │${" ".repeat(17)}`

/** Lines stay readable in a 100-column terminal. */
const MAX_WIDTH = 100

/** Comma list of up to 3 items that fits `width`, then "(+n more)". Always shows the first. */
function fitList(items: string[], width: number): string {
  const shown: string[] = []
  for (const item of items.slice(0, 3)) {
    const rest = items.length - shown.length - 1
    const candidate = [...shown, item].join(", ") + (rest > 0 ? ` (+${rest} more)` : "")
    if (shown.length && candidate.length > width) break
    shown.push(item)
  }
  const more = items.length - shown.length
  return more > 0 ? `${shown.join(", ")} ${pc.dim(`(+${more} more)`)}` : shown.join(", ")
}

/** Wrap a comma list into lines no wider than `width`. */
function wrapList(items: string[], width: number): string[] {
  const lines: string[] = []
  let current = ""
  for (const item of items) {
    const next = current ? `${current}, ${item}` : item
    if (current && next.length > width) {
      lines.push(`${current},`)
      current = item
    } else current = next
  }
  if (current) lines.push(current)
  return lines
}

const SUBRESOURCE_LIMIT = 50

const HEADER_NAMES: Array<[keyof Omit<HeadersAudit, "early_hints_seen" | "server_leak">, string]> = [
  ["hsts", "Strict-Transport-Security"],
  ["csp", "Content-Security-Policy"],
  ["x_frame_options", "X-Frame-Options"],
  ["x_content_type_options", "X-Content-Type-Options"],
  ["referrer_policy", "Referrer-Policy"],
  ["permissions_policy", "Permissions-Policy"],
  ["coop", "Cross-Origin-Opener-Policy"],
  ["coep", "Cross-Origin-Embedder-Policy"],
  ["corp", "Cross-Origin-Resource-Policy"],
]

const ms = (value: number | null | undefined) => (value == null ? "-" : `${Math.round(value)}ms`)

function glyph(status: ProbeStatus | undefined): string {
  if (status === "pass") return pc.green("✓")
  if (status === "warn") return pc.yellow("⚠")
  if (status === "fail") return pc.red("✗")
  return pc.dim("–")
}

const SKIP_REASON: Record<string, string> = {
  upstream_failed: "no response",
  not_applicable: "not applicable",
  disabled_by_flag: "disabled",
  rate_limited: "rate limited",
}

function skippedText(result: ProbeResult<unknown>): string {
  return pc.dim(`skipped (${SKIP_REASON[result.skipped?.reason ?? ""] ?? result.skipped?.reason ?? "no data"})`)
}

const row = (label: string, value: string, indent = 4) => `${" ".repeat(indent)}${label.padEnd(LABEL)} ${value}`
const date = (epochSeconds: number) => new Date(epochSeconds * 1000).toISOString().slice(0, 10)

function bytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

/** "CN=Foo CA 1" from an issuer DN; falls back to O=, then the raw string. */
function issuerName(dn: string): string {
  return /CN=([^,\n]+?)(?=\s+[A-Z]{1,2}=|$)/.exec(dn)?.[1] ?? /O=([^,\n]+?)(?=\s+[A-Z]{1,2}=|$)/.exec(dn)?.[1] ?? dn
}

/** "1AF6:27C6:…:EFFB" from a colon-separated SHA-256 fingerprint. */
function shortFingerprint(fp: string): string {
  const groups = fp.replace(/:/g, "").match(/.{1,4}/g) ?? []
  return groups.length > 3 ? `${groups[0]}:${groups[1]}:…:${groups[groups.length - 1]}` : fp
}

function header(trace: Trace): string[] {
  const title = `${pc.bold("◆ poirot")} ${pc.bold(`v${trace.runner.version}`)}  ·  ${trace.input.raw} → ${pc.cyan(trace.input.url)}`
  return [title, pc.dim("─".repeat(60))]
}

function domainBlock(trace: Trace): string[] {
  const { rdap, dns, email } = trace.domain
  const lines = ["", `  ${pc.bold("Domain")}`]
  if (rdap.status === "skipped" && dns.status === "skipped" && email.status === "skipped") {
    lines.push(row("", skippedText(rdap)).replace(/^\s+/, "    "))
    return lines
  }

  const r = rdap.data
  if (r?.registrar) {
    const created = r.created ? ` (created ${date(r.created)}, age ${Math.floor((Date.now() / 1000 - r.created) / 31_557_600)}y)` : ""
    lines.push(row("Registrar", `${r.registrar}${pc.dim(created)}`))
  } else {
    lines.push(row("Registrar", rdap.status === "skipped" ? skippedText(rdap) : pc.dim("unknown")))
  }
  if (r?.expires) {
    const left = r.days_to_expiry ?? Math.floor((r.expires * 1000 - Date.now()) / 86_400_000)
    const mark = left < 0 ? glyph("fail") : left < 30 ? glyph("warn") : glyph("pass")
    lines.push(row("Expires", `${date(r.expires)}  ${mark} ${left}d left`))
  }

  const d = dns.data
  if (d) {
    lines.push(row("DNSSEC", d.dnssec?.signed ? pc.green("signed") : pc.dim("not signed")))
    lines.push(row("Nameservers", fitList(d.ns, MAX_WIDTH - 4 - LABEL - 1) || pc.dim("none")))
  } else if (dns.status !== "pass") {
    lines.push(row("DNS", dns.status === "skipped" ? skippedText(dns) : `${glyph(dns.status)} ${dns.issues[0]?.code ?? "failed"}`))
  }

  const e = email.data
  if (e) {
    const dkimFound = Object.keys(e.dkim ?? {}).length
    // Null MX (RFC 7505): the domain sends no mail, so SPF/DMARC/DKIM are not evaluated.
    if (e.null_mx) lines.push(row("Email stack", pc.dim("not checked (domain does not send or receive mail)")))
    else lines.push(
      row(
        "Email stack",
        `SPF ${glyph(e.spf?.record ? "pass" : "fail")}  DMARC ${glyph(e.dmarc?.record ? "pass" : "fail")}  DKIM ${dkimFound ? `${dkimFound} found` : pc.dim("none found")}`,
      ),
    )
    const mx = e.null_mx
      ? "MX: null (RFC 7505) — domain rejects mail"
      : e.mx.length
        ? `MX: ${e.mx.map((m) => `${m.priority} ${m.host}`).join(", ")}`
        : "MX: none"
    lines.push(row("", pc.dim(mx)))
  } else if (email.status === "skipped") {
    lines.push(row("Email stack", skippedText(email)))
  }
  return lines
}

/** The attempt to draw the tree for: the one that answered, else the one that got furthest. */
function primaryAttempt(request: RequestTrace): NetworkAttempt | undefined {
  if (request.primaryStack === "v4") return request.attempts.v4
  if (request.primaryStack === "v6") return request.attempts.v6
  return request.attempts.v4 ?? request.attempts.v6
}

function stageLine(prefix: string, name: string, result: ProbeResult<unknown>, detail: string): string {
  const head = `    ${prefix} ${name.padEnd(5)}`
  // A later stage skipped because an earlier one failed: the failure is on the line above.
  if (result.status === "skipped") return `${head} ${"".padStart(6)}   ${pc.dim("skipped")}`
  const failure = result.status === "fail" ? result.issues.find((issue) => issue.severity === "fail") ?? result.issues[0] : undefined
  const time = ms(result.timing?.duration_ms).padStart(6)
  if (failure && !result.data) return `${head} ${time}   ${pc.red(`✗ ${failure.code}`)}  ${pc.dim(failure.message)}`
  return `${head} ${time}   ${detail}`
}

function tree(attempt: NetworkAttempt, verbose: boolean): string[] {
  const lines: string[] = []
  const dns = attempt.dns.data
  lines.push(stageLine("├─", "dns", attempt.dns, dns ? `via ${dns.resolver}  ${pc.cyan(dns.chosen_ip)} (${attempt.stack})` : ""))
  lines.push(stageLine("├─", "tcp", attempt.tcp, pc.cyan(`${attempt.network_peer_address}:${attempt.network_peer_port}`)))
  const tls = attempt.tls.data
  if (attempt.tls.status !== "skipped" || attempt.tls.skipped?.reason !== "not_applicable") {
    lines.push(stageLine("├─", "tls", attempt.tls, tls ? `TLS ${tls.protocol_version}  ${tls.cipher}  ALPN ${tls.alpn ?? "-"}` : ""))
    if (tls) {
      const leaf = tls.cert_leaf
      const expiry = leaf.days_to_expiry < 0 ? pc.red(`expired ${-leaf.days_to_expiry}d ago`) : `${leaf.days_to_expiry}d`
      lines.push(`${CONTINUATION}${pc.dim("cert")} ${issuerName(leaf.issuer)}`)
      lines.push(`${CONTINUATION}${pc.dim("expires")} ${date(leaf.not_after)} (${expiry})  ${pc.dim(`fp sha256 ${shortFingerprint(leaf.fingerprint_sha256)}`)}`)
      if (verbose && leaf.san.length) {
        wrapList(leaf.san, MAX_WIDTH - CONTINUATION.length - 5).forEach((chunk, i) =>
          lines.push(`${CONTINUATION}${i === 0 ? pc.dim("SAN") : "   "}  ${chunk}`),
        )
      }
    }
  }
  const http = attempt.http.data
  const server = http?.headers.find(([name]) => name.toLowerCase() === "server")?.[1]
  const httpDetail = http
    ? [http.protocol, bytes(http.body.bytes_received), http.body.encoding, http.body.content_type?.split(";")[0], server && pc.dim(`server: ${server}`)]
        .filter(Boolean)
        .join("  ")
    : ""
  lines.push(stageLine("└─", "http", attempt.http, httpDetail))
  if (verbose && http) {
    lines.push("", `    ${pc.bold("Response headers")}`)
    for (const [name, value] of http.headers) lines.push(`      ${pc.dim(`${name}: ${value}`)}`)
  }
  return lines
}

function attemptSummary(attempt: NetworkAttempt): string {
  const http = attempt.http.data
  const label = `${attempt.stack}:`
  if (!http) {
    const failed = [attempt.dns, attempt.tcp, attempt.tls, attempt.http].find((stage) => stage.status === "fail")
    return `      ${label} ${pc.yellow("fail")}   ${failed?.issues[0]?.code ?? "no response"}`
  }
  const total = (attempt.timings.dns ?? 0) + (attempt.timings.connect ?? 0) + (attempt.timings.ssl ?? 0) + (attempt.timings.wait ?? 0) + (attempt.timings.receive ?? 0)
  return `      ${label} ${ms(total).padEnd(6)} ${pc.cyan(attempt.network_peer_address.padEnd(20))} ${http.protocol.padEnd(4)} ${http.status}`
}

function dualStackLines(request: RequestTrace): string[] {
  const { v4, v6 } = request.attempts
  if (!v4 || !v6 || (!v4.http.data && !v6.http.data)) return []
  const lines = ["", `    ${pc.bold("Stacks")}`, attemptSummary(v4), attemptSummary(v6)]
  const bothOk = v4.http.data && v6.http.data
  const sameCert = !v4.tls.data || !v6.tls.data || v4.tls.data.cert_leaf.fingerprint_sha256 === v6.tls.data.cert_leaf.fingerprint_sha256
  const failed = !v4.http.data ? v4 : !v6.http.data ? v6 : undefined
  const failedIssues = failed ? [failed.dns, failed.tcp, failed.tls, failed.http].flatMap((stage) => stage.issues) : []
  if (bothOk && sameCert) lines.push(`      ${glyph("pass")} dual-stack consistent`)
  // Synthesis demotes a one-stack failure to info when the other stack works
  // (typically: this machine has no IPv6 route). Not a finding about the site.
  else if (failed && failedIssues.every((issue) => issue.severity === "info"))
    lines.push(`      ${pc.dim(`– only ${failed === v4 ? "v6" : "v4"} answered (${failed.stack} failure is informational)`)}`)
  else lines.push(`      ${glyph("warn")} dual-stack differs`)
  return lines
}

function auditsBlock(request: RequestTrace, verbose: boolean): string[] {
  const a = request.audits
  const lines = ["", `    ${pc.bold("Audits")}`]
  const r = (label: string, result: ProbeResult<unknown>, value: () => string) =>
    lines.push(row(label, result.status === "skipped" || !result.data ? skippedText(result) : value(), 6))

  r("Headers", a.headers, () => {
    const h = a.headers.data!
    const shown = `HSTS ${glyph(h.hsts.status)}  CSP ${glyph(h.csp.status)}  X-Frame ${glyph(h.x_frame_options.status)}  XCTO ${glyph(h.x_content_type_options.status)}`
    const others = [h.referrer_policy, h.permissions_policy, h.coop, h.coep, h.corp, h.server_leak].filter((entry) => entry.status !== "pass").length
    return others ? `${shown}  ${pc.dim(`(${others} more)`)}` : shown
  })
  if (verbose && a.headers.data) {
    const h = a.headers.data
    for (const [key, name] of HEADER_NAMES) {
      const entry = h[key] as { status: ProbeStatus; value?: string }
      // Full values are under "Response headers"; here one line per header.
      const room = MAX_WIDTH - 8 - 30 - 4
      const value = entry.value && entry.value.length > room ? `${entry.value.slice(0, room - 1)}…` : entry.value
      lines.push(`        ${name.padEnd(30)} ${glyph(entry.status)}  ${value ?? pc.dim("(missing)")}`)
    }
    const leak = [h.server_leak.server && `Server: ${h.server_leak.server}`, h.server_leak.x_powered_by && `X-Powered-By: ${h.server_leak.x_powered_by}`].filter(Boolean)
    if (leak.length) lines.push(`        ${"Version disclosure".padEnd(30)} ${glyph(h.server_leak.status)}  ${leak.join("  ")}`)
  }
  r("Cookies", a.cookies, () => {
    const cookies = a.cookies.data!.cookies
    if (!cookies.length) return pc.dim("(none set)")
    const flagged = cookies.filter((cookie) => cookie.issues.length).length
    return `${cookies.length} set${flagged ? ` · ${pc.yellow(`${flagged} flagged`)}` : ""}`
  })
  r("Subresources", a.subresources, () => {
    const s = a.subresources.data!
    const counts = Object.entries(s.counts_by_type)
      .filter(([, n]) => n > 0)
      .map(([tag, n]) => `${n} ${tag}`)
      .join(", ")
    return `${counts || "none"} · ${s.mixed_content_count} mixed-content · ${s.sri_missing_count} without SRI`
  })
  if (verbose && a.subresources.data?.resources.length) {
    const resources = a.subresources.data.resources
    for (const resource of resources.slice(0, SUBRESOURCE_LIMIT)) {
      const flags = [resource.mixed_content && pc.red("mixed"), resource.origin === "cross" && !resource.has_integrity && pc.dim("no SRI")].filter(Boolean).join(" ")
      lines.push(`        ${resource.tag.padEnd(7)} ${resource.url}${flags ? `  ${flags}` : ""}`)
    }
    if (resources.length > SUBRESOURCE_LIMIT) lines.push(`        ${pc.dim(`… ${resources.length - SUBRESOURCE_LIMIT} more`)}`)
  }
  r("Hosting", a.hosting, () => {
    const h = a.hosting.data!
    const parts = [h.asn ? `AS${h.asn} ${h.asn_org ?? ""}`.trim() : "ASN unknown"]
    if (h.cdn.detected) parts.push(`CDN ${h.cdn.name}`)
    if (h.waf.detected) parts.push(`WAF ${h.waf.name}`)
    return parts.join(" · ")
  })
  r("security.txt", a.securityTxt, () => (a.securityTxt.data!.present ? `${glyph("pass")} present` : `${glyph("fail")} not present`))
  r("HTTP/3", a.http3, () => {
    const h = a.http3.data!
    if (!h.advertised) return pc.dim("not advertised")
    return `advertised (${[h.via_alt_svc && "Alt-Svc", h.via_https_record && "HTTPS record"].filter(Boolean).join(", ")})`
  })
  return lines
}

function requestBlock(request: RequestTrace, index: number, verbose: boolean): string[] {
  const res = request.response
  const status = !res
    ? pc.red("✗ no response")
    : request.redirectsTo
      ? `${res.status} → ${pc.cyan(request.redirectsTo)}`
      : `${res.status} ${STATUS_CODES[res.status] ?? ""}`.trim()
  const lines = ["", `  ${pc.bold(`Request ${index + 1}`)}    GET ${pc.cyan(request.url)}    ${status}    ${ms(request.timing.duration_ms)}`]
  const attempt = primaryAttempt(request)
  if (attempt) lines.push(...tree(attempt, verbose))
  else lines.push(`    ${pc.dim("no address for either IPv4 or IPv6")}`)
  lines.push(...dualStackLines(request))
  if (verbose) {
    const curls = [request.attempts.v4, request.attempts.v6].filter((a) => a?.curl_command).map((a) => `      ${pc.dim(`${a!.stack}:`)} ${a!.curl_command}`)
    if (curls.length) lines.push("", `    ${pc.bold("Reproduce")}`, ...curls)
  }
  lines.push(...auditsBlock(request, verbose))
  return lines
}

/** Unique by code; fails first, then warns (and infos in verbose mode). */
function reportedIssues(trace: Trace, verbose: boolean): Issue[] {
  const rank = { fail: 0, warn: 1, info: 2 } as const
  const byCode = new Map<string, Issue>()
  for (const issue of collectIssues(trace)) {
    const existing = byCode.get(issue.code)
    if (!existing || rank[issue.severity] < rank[existing.severity]) byCode.set(issue.code, issue)
  }
  return [...byCode.values()]
    .filter((issue) => verbose || issue.severity !== "info")
    .sort((a, b) => rank[a.severity] - rank[b.severity])
}

function verdictBlock(trace: Trace, verbose: boolean): string[] {
  const s = trace.synthesis
  const issues = reportedIssues(trace, verbose)
  const counted = issues.filter((issue) => issue.severity !== "info").length
  const color = s.verdict === "fail" ? pc.red : s.verdict === "warn" ? pc.yellow : pc.green
  const lines = [
    "",
    `  ${pc.bold("Verdict")}  ${color(s.verdict)}  ·  ${pc.bold("Grade")}  ${color(s.grade)}  (${s.score}/100)  ·  ${counted} ${counted === 1 ? "issue" : "issues"}`,
  ]
  const width = Math.max(0, ...issues.map((issue) => issue.code.length))
  for (const issue of issues) {
    const mark = issue.severity === "fail" ? glyph("fail") : issue.severity === "warn" ? glyph("warn") : pc.dim("·")
    lines.push(`    ${mark}  ${pc.bold(issue.code.padEnd(width))}  ${pc.dim(issue.message)}`)
    if (issue.advice) lines.push(`       ${"".padEnd(width)}  Fix: ${issue.advice}`)
    if (issue.doc) lines.push(`       ${"".padEnd(width)}  ${pc.dim(`Doc: ${issue.doc}`)}`)
  }
  return lines
}

export function renderPretty(trace: Trace, opts: RenderOpts): string {
  const lines = [
    ...header(trace),
    ...domainBlock(trace),
    ...trace.requests.flatMap((request, index) => requestBlock(request, index, opts.verbose)),
    ...verdictBlock(trace, opts.verbose),
    "",
    pc.dim(`  Total ${Math.round(trace.synthesis.timings.total_ms)} ms · schemaVersion ${trace.schemaVersion} · algorithm v${trace.synthesis.audit_algorithm_version}`),
  ]
  return lines.join("\n")
}
