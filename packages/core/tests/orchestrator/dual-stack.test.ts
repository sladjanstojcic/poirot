import http from "node:http"
import https from "node:https"
import { afterEach, describe, expect, it, vi } from "vitest"

// Stub DNS so tests don't depend on real resolvers.
vi.mock("/src/net/dns-packet.js", () => ({
  dnsQuery: vi.fn(async (name: string, type: string) => ({
    id: 0,
    type: "response",
    flags: 0,
    questions: [],
    answers: type === "A" ? [{ name, type: "A", class: "IN", ttl: 60, data: "127.0.0.1" }] : [],
  })),
}))

import { dualStack } from "../../src/orchestrator/dual-stack.js"
import { dnsQuery } from "../../src/net/dns-packet.js"
import { makeSelfSigned } from "../fixtures/self-signed-cert.js"

let server: http.Server | https.Server | null = null

afterEach(
  () =>
    new Promise<void>((resolve) => {
      if (server) {
        server.close(() => resolve())
      } else {
        resolve()
      }
    }),
)

describe("dualStack orchestrator", () => {
  it(
    "returns primary='v4' when v4 resolves and v6 has no answer",
    async () => {
      server = http
        .createServer((_, res) => {
          res.writeHead(200).end("ok")
        })
        .listen(0, "127.0.0.1")
      await new Promise<void>((resolve) => server?.once("listening", () => resolve()))
      const address = server.address() as any
      const r = await dualStack({ url: `http://127.0.0.1:${address.port}/`, opts: { timeout: 3000 } })
      expect(r.primary).toBe("v4")
      expect(r.v4?.http.data?.status).toBe(200)
      expect(r.v6).toBeUndefined()
    },
    10000,
  )

  it(
    "returns primary='none' when v4 fetch fails (closed port) and v6 has no answer",
    async () => {
      const r = await dualStack({
        url: "http://127.0.0.1:1/",
        opts: { timeout: 500 },
      })
      expect(r.primary).toBe("none")
    },
    5000,
  )

  it(
    "self-signed HTTPS server still gets an HTTP exchange",
    async () => {
      const { cert, key } = await makeSelfSigned()
      server = https
        .createServer({ cert, key }, (_, res) => {
          res.writeHead(200).end("ok")
        })
        .listen(0, "127.0.0.1")
      await new Promise<void>((resolve) => server?.once("listening", () => resolve()))
      const address = server.address() as any
      const r = await dualStack({ url: `https://127.0.0.1:${address.port}/`, opts: { timeout: 3000 } })
      expect(r.v4?.tls.issues.some((issue) => issue.code === "CERT_UNTRUSTED")).toBe(true)
      expect(r.primary).toBe("v4")
      expect(r.v4?.http.data?.status).toBe(200)
    },
    15000,
  )

  it(
    "DNS failure is kept in the attempt",
    async () => {
      vi.mocked(dnsQuery).mockRejectedValueOnce(new Error("DNS_TIMEOUT")).mockRejectedValueOnce(new Error("DNS_TIMEOUT"))
      const r = await dualStack({ url: "https://h.test/", opts: { timeout: 3000, dns: "192.0.2.53" } })
      expect(r.primary).toBe("none")
      expect(r.v4?.dns.status).toBe("fail")
      expect(r.v4?.dns.issues[0]?.code).toBe("DNS_TIMEOUT")
      expect(r.v4?.tcp.status).toBe("skipped")
    },
    10000,
  )
})
