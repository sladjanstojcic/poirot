import net from "node:net"
import { performance } from "node:perf_hooks"
import { ISSUE } from "../../issues/codes.js"
import { defineProbe, isDeadline } from "../../probe.js"
import type { TcpConnect } from "../../types/index.js"

export interface TcpConnectInput {
  ip: string
  port: number
  timeout_ms?: number
}

export const tcpConnect = defineProbe<TcpConnectInput, TcpConnect>(
  "tcpConnect",
  ["connected", "port"],
  async ({ ip, port, timeout_ms = 5000 }, ctx) => {
    const t0 = performance.now()
    const result = await new Promise<
      { ok: true; data: TcpConnect } | { ok: false; code: string; msg: string }
    >((resolve) => {
      const sock = net.createConnection({ host: ip, port, family: net.isIPv6(ip) ? 6 : 4 })
      const timer = setTimeout(() => {
        sock.destroy()
        resolve({ ok: false, code: ISSUE.TCP_TIMEOUT, msg: "TCP connect timeout" })
      }, timeout_ms)
      const onAbort = () => {
        clearTimeout(timer)
        sock.destroy()
        resolve(
          isDeadline(ctx.signal)
            ? { ok: false, code: ISSUE.TCP_TIMEOUT, msg: "deadline exceeded" }
            : { ok: false, code: ISSUE.TCP_ERROR, msg: "aborted" },
        )
      }
      if (ctx.signal.aborted) return onAbort()
      ctx.signal.addEventListener("abort", onAbort, { once: true })
      sock.once("connect", () => {
        clearTimeout(timer)
        ctx.signal.removeEventListener("abort", onAbort)
        const local = sock.address() as net.AddressInfo
        sock.end()
        resolve({
          ok: true,
          data: {
            ip,
            port,
            connected: true,
            connect_ms: +(performance.now() - t0).toFixed(1),
            local_address: local.address,
          },
        })
      })
      sock.once("error", (err: any) => {
        clearTimeout(timer)
        ctx.signal.removeEventListener("abort", onAbort)
        const code = err.code === "ECONNREFUSED"
          ? "TCP_REFUSED"
          : err.code === "EHOSTUNREACH" || err.code === "ENETUNREACH"
            ? "TCP_UNREACHABLE"
            : "TCP_ERROR"
        resolve({ ok: false, code, msg: err.message })
      })
    })
    if (!result.ok) {
      return {
        status: "fail",
        issues: [{ severity: "fail", code: result.code, message: result.msg }],
      }
    }
    return { status: "pass", data: result.data }
  },
)
