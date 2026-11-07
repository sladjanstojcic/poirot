import { performance } from "node:perf_hooks"
import type { AddressInfo } from "node:net"
import tls from "node:tls"
import { afterEach, describe, expect, it } from "vitest"
import { tlsHandshake } from "../../../src/probes/phase2/tls-handshake.js"
import { makeSelfSigned } from "../../fixtures/self-signed-cert.js"

const LIVE = process.env.POIROT_LIVE === "1"
const ctx = {
  traceStart: performance.now(),
  signal: new AbortController().signal,
  flags: {},
  cache: new Map(),
  logger: () => {},
}

let server: tls.Server | null = null

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

describe("tlsHandshake", () => {
  it.runIf(LIVE)(
    "handshakes with example.com over h2",
    async () => {
      const r = await tlsHandshake({ hostname: "example.com", ip: "example.com", port: 443 }, ctx)
      expect(r.status).toBe("pass")
      expect(r.data?.protocol_version).toMatch(/^1\.(2|3)$/)
      expect(r.data?.cert_leaf.fingerprint_sha256).toMatch(/^[A-F0-9:]{95,}$/)
      expect(r.data?.kex).toBeDefined()
      expect(typeof r.data?.kex.name).toBe("string")
    },
    15000,
  )

  it(
    "emits CERT_UNTRUSTED against a local self-signed server but still captures handshake metadata",
    async () => {
      const { cert, key } = await makeSelfSigned()
      server = tls.createServer({ cert, key, ALPNProtocols: ["h2", "http/1.1"] }, (socket) => socket.end()).listen(0, "127.0.0.1")
      await new Promise<void>((resolve) => server?.once("listening", () => resolve()))
      const address = server.address() as AddressInfo
      const r = await tlsHandshake({ hostname: "127.0.0.1", ip: "127.0.0.1", port: address.port }, ctx)
      expect(r.data?.protocol_version).toMatch(/^1\.(2|3)$/)
      expect(r.data?.cert_leaf.fingerprint_sha256).toMatch(/^[A-F0-9:]{95,}$/)
      expect(r.issues.some((issue) => issue.code === "CERT_UNTRUSTED")).toBe(true)
    },
    15000,
  )

  it(
    "maps connect error to TLS_TIMEOUT code on unreachable port",
    async () => {
      const r = await tlsHandshake({ hostname: "127.0.0.1", ip: "127.0.0.1", port: 1, timeout_ms: 500 }, ctx)
      expect(r.status).toBe("fail")
      expect(r.issues.some((issue) => issue.code === "TLS_TIMEOUT" || issue.code === "PROBE_THREW")).toBe(true)
    },
    5000,
  )

  it(
    "TLS 1.2 server does not emit TLS_WEAK_VERSION",
    async () => {
      const { cert, key } = await makeSelfSigned()
      server = tls.createServer({ cert, key, maxVersion: "TLSv1.2" }, (socket) => socket.end()).listen(0, "127.0.0.1")
      await new Promise<void>((resolve) => server?.once("listening", () => resolve()))
      const address = server.address() as AddressInfo
      const r = await tlsHandshake({ hostname: "127.0.0.1", ip: "127.0.0.1", port: address.port }, ctx)
      expect(r.data?.protocol_version).toBe("1.2")
      expect(r.issues.some((issue) => issue.code === "TLS_WEAK_VERSION")).toBe(false)
    },
    15000,
  )

  it(
    "hostname not in SAN emits CERT_NAME_MISMATCH",
    async () => {
      const { cert, key } = await makeSelfSigned()
      server = tls.createServer({ cert, key }, (socket) => socket.end()).listen(0, "127.0.0.1")
      await new Promise<void>((resolve) => server?.once("listening", () => resolve()))
      const address = server.address() as AddressInfo
      const r = await tlsHandshake({ hostname: "wrong.example", ip: "127.0.0.1", port: address.port }, ctx)
      const mismatch = r.issues.find((issue) => issue.code === "CERT_NAME_MISMATCH")
      expect(mismatch?.severity).toBe("fail")
      expect(r.status).toBe("fail")
    },
    15000,
  )

  it(
    "matching IP SAN does not emit CERT_NAME_MISMATCH",
    async () => {
      const { cert, key } = await makeSelfSigned()
      server = tls.createServer({ cert, key }, (socket) => socket.end()).listen(0, "127.0.0.1")
      await new Promise<void>((resolve) => server?.once("listening", () => resolve()))
      const address = server.address() as AddressInfo
      const r = await tlsHandshake({ hostname: "127.0.0.1", ip: "127.0.0.1", port: address.port }, ctx)
      expect(r.issues.some((issue) => issue.code === "CERT_NAME_MISMATCH")).toBe(false)
    },
    15000,
  )

  it(
    "no timer survives a successful handshake",
    async () => {
      const { cert, key } = await makeSelfSigned()
      server = tls.createServer({ cert, key }, (socket) => socket.end()).listen(0, "127.0.0.1")
      await new Promise<void>((resolve) => server?.once("listening", () => resolve()))
      const address = server.address() as AddressInfo
      const timers = () => process.getActiveResourcesInfo().filter((r) => r === "Timeout").length
      const before = timers()
      await tlsHandshake({ hostname: "127.0.0.1", ip: "127.0.0.1", port: address.port, timeout_ms: 30_000 }, ctx)
      await new Promise((resolve) => setImmediate(resolve))
      expect(timers()).toBeLessThanOrEqual(before)
    },
    15000,
  )

  it(
    "deadline during handshake reports TLS_TIMEOUT promptly",
    async () => {
      // Server accepts TCP but never speaks TLS.
      const net = await import("node:net")
      const raw = net.createServer(() => {}).listen(0, "127.0.0.1")
      await new Promise<void>((resolve) => raw.once("listening", () => resolve()))
      const controller = new AbortController()
      setTimeout(() => controller.abort(new Error("POIROT_DEADLINE")), 200)
      const t0 = Date.now()
      const r = await tlsHandshake(
        { hostname: "127.0.0.1", ip: "127.0.0.1", port: (raw.address() as AddressInfo).port, timeout_ms: 30_000 },
        { ...ctx, signal: controller.signal },
      )
      raw.close()
      expect(Date.now() - t0).toBeLessThan(2000)
      expect(r.issues[0]?.code).toBe("TLS_TIMEOUT")
    },
    15000,
  )
})
