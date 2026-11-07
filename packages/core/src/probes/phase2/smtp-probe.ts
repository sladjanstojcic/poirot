import net from "node:net"
import { ISSUE } from "../../issues/codes.js"
import { defineProbe } from "../../probe.js"
import type { Issue, SmtpProbeResult } from "../../types/index.js"

export interface SmtpProbeInput {
  mx: Array<{ host: string; priority: number }>
  timeout_ms?: number
}

async function probeOne(
  host: string,
  timeoutMs: number,
): Promise<{ connected: boolean; greeting?: string; supports_starttls?: boolean; error?: string }> {
  return new Promise((resolve) => {
    const sock = net.createConnection({ host, port: 25 })
    let buf = ""
    const timer = setTimeout(() => {
      sock.destroy()
      resolve({ connected: false, error: "timeout" })
    }, timeoutMs)
    sock.once("error", (e) => {
      clearTimeout(timer)
      resolve({ connected: false, error: (e as any).code ?? "error" })
    })
    sock.on("data", (d) => {
      buf += d.toString()
      if (!/^220[ -]/.test(buf)) return
      const greeting = buf.split(/\r?\n/)[0]
      sock.write("EHLO poirot.local\r\n")
      sock.once("data", (d2) => {
        buf = d2.toString()
        clearTimeout(timer)
        sock.end()
        resolve({ connected: true, greeting, supports_starttls: /STARTTLS/i.test(buf) })
      })
    })
  })
}

export const smtpProbe = defineProbe<SmtpProbeInput, SmtpProbeResult>(
  "smtpProbe",
  ["reachable", "hosts"],
  async ({ mx, timeout_ms = 5000 }, ctx) => {
    if (!ctx.flags.probe_smtp) {
      return { status: "skipped", skipped: { reason: "disabled_by_flag" } }
    }
    const hosts = await Promise.all(
      mx.map(async (m) => {
        const r = await probeOne(m.host, timeout_ms)
        return {
          host: m.host,
          priority: m.priority,
          connected: r.connected,
          greeting: r.greeting,
          supports_starttls: r.supports_starttls,
          error: r.error,
        }
      }),
    )
    const reachable = hosts.some((h) => h.connected)
    const issues: Issue[] = []
    if (!reachable) {
      issues.push({ severity: "warn", code: ISSUE.SMTP_UNREACHABLE, message: "All MX hosts failed" })
    }
    const noStarttls = hosts.filter((h) => h.connected && !h.supports_starttls)
    if (noStarttls.length) {
      issues.push({
        severity: "warn",
        code: ISSUE.SMTP_NO_STARTTLS,
        message: `${noStarttls.length} MX do not advertise STARTTLS`,
      })
    }
    return {
      status: issues.some((i) => i.severity === "fail") ? "fail" : issues.length ? "warn" : "pass",
      data: { reachable, hosts },
      issues,
    }
  },
)
