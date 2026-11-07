import crypto from "node:crypto"
import { performance } from "node:perf_hooks"
// Subpath import on purpose: Bun maps bare "undici" to a built-in shim whose
// Client.request() resolves undefined, which breaks `bun build --compile` binaries.
import { buildConnector, Client } from "undici/index.js"
import { ISSUE } from "../../issues/codes.js"
import { defineProbe, isDeadline } from "../../probe.js"
import type { HttpExchange, Issue } from "../../types/index.js"

export interface HttpExchangeInput {
  url: string
  method: "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS"
  user_agent: string
  allowH2: boolean
  body_cap_bytes?: number
  timeout_ms?: number
  pin_ip?: string
}

function buildCurl(url: URL, method: string, ua: string, allowH2: boolean, pin_ip?: string): string {
  const parts = [
    "curl",
    allowH2 ? "-2v" : "-v",
    `-A "${ua.replace(/"/g, '\\"')}"`,
    `-X ${method}`,
  ]
  if (pin_ip) {
    parts.push(`--resolve ${url.host}:${url.port || (url.protocol === "https:" ? 443 : 80)}:${pin_ip}`)
  }
  parts.push(`"${url.toString()}"`)
  return parts.join(" ")
}

// buildConnector returns the low-level dialer. We wrap it to override the dial target host.
const baseConnector = buildConnector({ rejectUnauthorized: false })

export const httpExchange = defineProbe<HttpExchangeInput, HttpExchange>(
  "httpExchange",
  ["protocol", "status", "headers", "body.sha256", "body.content_type", "body.encoding"],
  async (input, ctx) => {
    const url = new URL(input.url)
    const client = new Client(`${url.protocol}//${url.host}`, {
      allowH2: input.allowH2,
      connectTimeout: input.timeout_ms ?? 5000,
      bodyTimeout: input.timeout_ms ?? 10000,
      headersTimeout: input.timeout_ms ?? 10000,
      connect: input.pin_ip
        ? ((opts: any, cb: any) => baseConnector({ ...opts, hostname: input.pin_ip!, host: input.pin_ip! }, cb))
        : undefined,
    } as any)
    const issues: Issue[] = []
    const t0 = performance.now()

    let res: any
    try {
      res = await client.request({
        method: input.method,
        path: `${url.pathname}${url.search}` || "/",
        headers: { "user-agent": input.user_agent, host: url.host, accept: "*/*" },
        signal: ctx.signal,
      })
    } catch (error: any) {
      await client.close().catch(() => {})
      const name = String(error?.name ?? "")
      const code = isDeadline(ctx.signal) || ctx.signal.aborted || /Timeout|HeadersTimeout|BodyTimeout|ConnectTimeout/i.test(name)
        ? "HTTP_TIMEOUT"
        : /Reset|SocketError/i.test(name)
          ? "HTTP_RESET"
          : "HTTP_MALFORMED"
      return {
        status: "fail",
        issues: [
          {
            severity: "fail",
            code,
            message: isDeadline(ctx.signal) ? "deadline exceeded" : name || String(error?.message ?? "error"),
          },
        ],
      }
    }

    const ttfb_ms = +(performance.now() - t0).toFixed(1)

    const cap = input.body_cap_bytes ?? 65536
    let received = 0
    const chunks: Buffer[] = []
    let truncated = false
    // Headers already arrived: a body that stalls (slow server, SSE stream) must
    // not discard the response. Keep what was read and report the stall.
    try {
      for await (const chunk of res.body as any) {
        const buffer = chunk as Buffer
        if (received + buffer.length <= cap) {
          chunks.push(buffer)
          received += buffer.length
        } else {
          chunks.push(buffer.subarray(0, cap - received))
          received = cap
          truncated = true
          break
        }
      }
    } catch (error: any) {
      issues.push({
        severity: "warn",
        code: ISSUE.HTTP_TIMEOUT,
        message: isDeadline(ctx.signal)
          ? `response body incomplete at deadline (${received} bytes read)`
          : `response body did not complete: ${String(error?.name ?? error?.message ?? "error")} (${received} bytes read)`,
      })
    }
    if (truncated) {
      issues.push({ severity: "info", code: ISSUE.HTTP_BODY_TRUNCATED, message: `body capped at ${cap} bytes` })
    }
    if (res.statusCode === 429) {
      const retryAfter = res.headers["retry-after"]
      issues.push({
        severity: "info",
        code: ISSUE.HTTP_RATE_LIMITED,
        message: `429 Too Many Requests${retryAfter ? ` (Retry-After: ${retryAfter})` : ""}`,
      })
    }
    const total_ms = +(performance.now() - t0).toFixed(1)
    await client.destroy().catch(() => {})

    const headers: Array<[string, string]> = []
    for (const [k, v] of Object.entries(res.headers)) {
      if (Array.isArray(v)) {
        v.forEach((value) => headers.push([k, String(value)]))
      } else if (v != null) {
        headers.push([k, String(v)])
      }
    }
    const protocol: HttpExchange["protocol"] = input.allowH2 ? "h2" : "http/1.1"
    const body = Buffer.concat(chunks)

    return {
      status: issues.some((issue) => issue.code === ISSUE.HTTP_TIMEOUT) ? "warn" : "pass",
      data: {
        protocol,
        status: res.statusCode,
        headers,
        body: {
          bytes_received: received,
          truncated_at: truncated ? cap : undefined,
          content_type: res.headers["content-type"] as string | undefined,
          encoding: res.headers["content-encoding"] as string | undefined,
          sha256: crypto.createHash("sha256").update(body).digest("hex"),
        },
        ttfb_ms,
        total_ms,
        curl_command: buildCurl(url, input.method, input.user_agent, input.allowH2, input.pin_ip),
      },
      issues,
    }
  },
)
