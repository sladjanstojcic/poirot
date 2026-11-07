import net from "node:net"
import { getDomain } from "tldts"
import { performance } from "node:perf_hooks"
import dkimSelectors from "../data/dkim-selectors.json" with { type: "json" }
import { toALabel } from "../net/idn.js"
import { DEADLINE_REASON, type ProbeCtx, type ProbeEvent } from "../probe.js"
import type { DomainContext, ProbeResult, RequestTrace, Trace } from "../types/index.js"
import { AUDIT_ALGORITHM_VERSION, SCHEMA_VERSION } from "../version.js"
import packageJson from "../../package.json" with { type: "json" }
import { detectRedirectLoop, nextHopUrl } from "./redirect-follow.js"
import { dualStack } from "./dual-stack.js"
import { runPhase1 } from "./phase1-runner.js"
import { runPhase3 } from "./phase3-runner.js"
import { synthesize } from "./synthesize.js"

export interface ProbeOptions {
  timeout?: number
  dns?: string
  userAgent?: string
  maxRedirects?: number
  probeSmtp?: boolean
  dkimSelectors?: string[]
  signal?: AbortSignal
  onEvent?: (event: ProbeEvent) => void
}

const DEFAULT_UA = `poirot/${(packageJson as any).version} (+https://github.com/sladjanstojcic/poirot)`

function normalizeInputUrl(raw: string): string {
  const trimmed = raw.trim()
  if (/^https?:\/\//i.test(trimmed)) return new URL(trimmed).toString()
  return new URL(`https://${trimmed}`).toString()
}

function skippedProbe<T>(
  reason: "upstream_failed" | "disabled_by_flag" | "not_applicable" | "rate_limited",
): ProbeResult<T> {
  return {
    status: "skipped",
    issues: [],
    timing: { startedAt_ms: 0, duration_ms: 0 },
    skipped: { reason },
    alertable_fields: [],
  }
}

// Special-use and private-network names (RFC 6761, RFC 8375, common LAN suffixes):
// no registry, no public DNS records, no mail setup to audit.
const LOCAL_SUFFIXES = [".localhost", ".local", ".internal", ".test", ".home.arpa", ".lan"]

function isLocalName(host: string): boolean {
  const name = host.toLowerCase().replace(/\.$/, "")
  return name === "localhost" || LOCAL_SUFFIXES.some((suffix) => name.endsWith(suffix))
}

async function maybeRunPhase1(domain: string, ctx: ProbeCtx, opts: ProbeOptions): Promise<DomainContext> {
  const registrableDomain = net.isIP(domain) || isLocalName(domain) ? null : getDomain(domain)
  if (!registrableDomain) {
    return {
      domain,
      rdap: skippedProbe("not_applicable"),
      dns: skippedProbe("not_applicable"),
      email: skippedProbe("not_applicable"),
    }
  }
  return runPhase1(
    {
      domain,
      registrableDomain,
      dnsResolver: opts.dns,
      dkimSelectors: opts.dkimSelectors?.length ? opts.dkimSelectors : (dkimSelectors as string[]),
    },
    ctx,
  )
}

export async function probe(inputUrl: string, opts: ProbeOptions = {}): Promise<Trace> {
  const traceStart = performance.now()
  const traceStartedAt = new Date().toISOString()
  const url = normalizeInputUrl(inputUrl)
  const parsed = new URL(url)
  const domain = toALabel(parsed.hostname)

  const controller = new AbortController()
  const onExternalAbort = () => controller.abort()
  if (opts.signal?.aborted) controller.abort()
  else if (opts.signal) opts.signal.addEventListener("abort", onExternalAbort, { once: true })
  const timeoutTimer = opts.timeout ? setTimeout(() => controller.abort(new Error(DEADLINE_REASON)), opts.timeout) : undefined
  timeoutTimer?.unref?.()

  const ctx: ProbeCtx = {
    traceStart,
    signal: controller.signal,
    flags: { probe_smtp: opts.probeSmtp ?? false, ...opts },
    cache: new Map(),
    logger: () => {},
    onEvent: opts.onEvent,
  }

  // Phase 1 (RDAP, DNS records, email) runs alongside the first request: a slow
  // or blocked record resolver must not delay or time out the request itself.
  const phase1Start = performance.now()
  ctx.onEvent?.({ type: "phase.start", phase: "hostname", at_ms: phase1Start - traceStart })
  const phase1 = maybeRunPhase1(domain, ctx, opts).then((result) => {
    ctx.onEvent?.({
      type: "phase.end",
      phase: "hostname",
      at_ms: performance.now() - traceStart,
      duration_ms: performance.now() - phase1Start,
    })
    return result
  })
  // Awaited later; mark handled now so an early rejection is not "unhandled".
  phase1.catch(() => {})

  const requests: RequestTrace[] = []
  const maxHops = opts.maxRedirects ?? 10
  const seen: string[] = []
  let current: string | null = url

  while (current && requests.length < maxHops) {
    seen.push(current)
    const hopStart = performance.now()
    const hopUrl = new URL(current)
    const { v4, v6, primary } = await dualStack({ url: current, opts, ctx } as any)
    const response = primary === "v4" ? v4?.http.data : primary === "v6" ? v6?.http.data : undefined
    const rawBody = (primary === "v4" ? (v4 as any)?.rawBody : (v6 as any)?.rawBody) ?? Buffer.alloc(0)
    const peerIp = primary === "v4" ? v4?.network_peer_address : primary === "v6" ? v6?.network_peer_address : ""

    const audits = await runPhase3(
      {
        url: current,
        origin: hopUrl.origin,
        response,
        rawBody,
        peerIp: peerIp ?? "",
        dnsHttpsRecords: (await phase1).dns.data?.https,
      },
      ctx,
    )

    const nextUrl: string | null = response ? nextHopUrl(current, response.status, response.headers) : null
    requests.push({
      url: current,
      attempts: { v4, v6 },
      primaryStack: primary,
      response,
      audits,
      redirectsTo: nextUrl ?? undefined,
      timing: { startedAt_ms: hopStart - traceStart, duration_ms: performance.now() - hopStart },
    })

    if (nextUrl && detectRedirectLoop(seen, nextUrl)) break
    current = nextUrl
  }

  const synthesisStart = performance.now()
  ctx.onEvent?.({ type: "phase.start", phase: "synthesis", at_ms: synthesisStart - traceStart })

  const trace: Trace = {
    schemaVersion: SCHEMA_VERSION,
    traceStartedAt,
    duration_ms: 0,
    input: { raw: inputUrl, url, userAgent: opts.userAgent ?? DEFAULT_UA, flags: { ...opts } },
    runner: {
      name: "poirot",
      version: (packageJson as any).version,
      runtime: (globalThis as any).Bun ? "bun" : "node",
      runtime_version: process.version,
    },
    domain: await phase1,
    requests,
    synthesis: {
      verdict: "pass",
      grade: "A",
      score: 100,
      worst_issues: [],
      timings: { total_ms: 0, by_phase: { hostname_context_ms: 0, network_ms: 0, audits_ms: 0, synthesis_ms: 0 } },
      change_hash: "",
      change_fields: [],
      audit_algorithm_version: AUDIT_ALGORITHM_VERSION,
    },
  }

  trace.duration_ms = performance.now() - traceStart
  trace.synthesis = synthesize(trace)
  trace.synthesis.timings.by_phase.synthesis_ms = performance.now() - synthesisStart

  ctx.onEvent?.({
    type: "phase.end",
    phase: "synthesis",
    at_ms: performance.now() - traceStart,
    duration_ms: performance.now() - synthesisStart,
  })

  // Guarantee the returned Trace is JSON-safe and round-trip stable.
  if (timeoutTimer) clearTimeout(timeoutTimer)
  opts.signal?.removeEventListener("abort", onExternalAbort)
  return JSON.parse(JSON.stringify(trace)) as Trace
}
