import { dnsResolve } from "../probes/phase2/dns-resolve.js"
import { httpExchange, responseBodies } from "../probes/phase2/http-exchange.js"
import { tcpConnect } from "../probes/phase2/tcp-connect.js"
import { tlsHandshake } from "../probes/phase2/tls-handshake.js"
import type { ProbeCtx } from "../probe.js"
import type { NetworkAttempt, ProbeResult, TlsHandshake } from "../types/index.js"

function skippedResult<T>(
  reason: "upstream_failed" | "disabled_by_flag" | "not_applicable" | "rate_limited",
  alertable_fields: string[] = [],
): ProbeResult<T> {
  return {
    status: "skipped",
    issues: [],
    timing: { startedAt_ms: 0, duration_ms: 0 },
    skipped: { reason },
    alertable_fields,
  }
}

export async function runStack(args: {
  hostname: string
  path: string
  stack: "v4" | "v6"
  port: number
  isHttps: boolean
  ctx: ProbeCtx
  userAgent: string
  resolver?: string
  timeout?: number
}): Promise<(NetworkAttempt & { rawBody: Buffer }) | undefined> {
  const { hostname, path, stack, port, isHttps, ctx, userAgent, resolver, timeout } = args

  const dns = await dnsResolve({ hostname, stack, resolver }, ctx)
  // "skipped" = no record for this address family: no attempt. A failed lookup
  // is kept, so the trace says why the stack never connected (NXDOMAIN, timeout).
  if (dns.status === "skipped") return undefined
  if (dns.status !== "pass") {
    return {
      stack,
      server_address: hostname,
      network_peer_address: "",
      network_peer_port: port,
      network_protocol_version: "1.1",
      timings: { dns: null, connect: null, ssl: null, send: null, wait: null, receive: null },
      dns,
      tcp: skippedResult("upstream_failed"),
      tls: skippedResult<TlsHandshake>("upstream_failed"),
      http: skippedResult("upstream_failed"),
      curl_command: "",
      rawBody: Buffer.alloc(0),
    } as any
  }

  const ip = dns.data!.chosen_ip
  const tcp = await tcpConnect({ ip, port, timeout_ms: timeout }, ctx)
  if (tcp.status !== "pass") {
    return {
      stack,
      server_address: hostname,
      network_peer_address: ip,
      network_peer_port: port,
      network_protocol_version: "1.1",
      timings: { dns: dns.data!.query_ms, connect: null, ssl: null, send: null, wait: null, receive: null },
      dns,
      tcp,
      tls: skippedResult<TlsHandshake>("upstream_failed"),
      http: skippedResult("upstream_failed"),
      curl_command: "",
      rawBody: Buffer.alloc(0),
    } as any
  }

  const tls = isHttps
    ? await tlsHandshake({ hostname, ip, port, timeout_ms: timeout }, ctx)
    : skippedResult<TlsHandshake>("not_applicable")
  // Stop only when no handshake completed. Cert problems (untrusted, expired,
  // name mismatch) are findings; the HTTP exchange still runs so they are shown
  // alongside the response (spec phase2 §3.6: "we still show the cert").
  if (isHttps && !tls.data) {
    return {
      stack,
      server_address: hostname,
      network_peer_address: ip,
      network_peer_port: port,
      network_protocol_version: "1.1",
      timings: {
        dns: dns.data!.query_ms,
        connect: tcp.data?.connect_ms ?? null,
        ssl: null,
        send: null,
        wait: null,
        receive: null,
      },
      dns,
      tcp,
      tls,
      http: skippedResult("upstream_failed"),
      curl_command: "",
      rawBody: Buffer.alloc(0),
    } as any
  }

  const allowH2 = tls.data?.alpn === "h2"
  const http = await httpExchange(
    {
      url: `${isHttps ? "https" : "http"}://${hostname}:${port}${path}`,
      method: "GET",
      user_agent: userAgent,
      allowH2,
      timeout_ms: timeout,
      pin_ip: isHttps ? ip : undefined,
    },
    ctx,
  )

  return {
    stack,
    server_address: hostname,
    network_peer_address: ip,
    network_peer_port: port,
    network_protocol_version: http.data?.protocol === "h2" ? "2" : "1.1",
    timings: {
      dns: dns.data!.query_ms,
      connect: tcp.data?.connect_ms ?? null,
      ssl: tls.data?.handshake_ms ?? null,
      send: null,
      wait: http.data?.ttfb_ms ?? null,
      receive: http.data ? http.data.total_ms - http.data.ttfb_ms : null,
    },
    dns,
    tcp,
    tls,
    http,
    curl_command: http.data?.curl_command ?? "",
    rawBody: (http.data && responseBodies.get(http.data)) ?? Buffer.alloc(0),
  } as any
}
