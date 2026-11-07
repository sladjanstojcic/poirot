import { performance } from "node:perf_hooks"
import type { AddressInfo } from "node:net"
import tls from "node:tls"
import { afterEach, describe, expect, it, vi } from "vitest"
import { tlsHandshake } from "../../../src/probes/phase2/tls-handshake.js"
import { makeSelfSigned } from "../../fixtures/self-signed-cert.js"

// Own file on purpose: Node emits each deprecation warning once per process,
// so this must run before any other test handshakes with an IP hostname.
const ctx = {
  traceStart: performance.now(),
  signal: new AbortController().signal,
  flags: {},
  cache: new Map(),
  logger: () => {},
}

let server: tls.Server | null = null
afterEach(() => new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve())))

describe("tlsHandshake against an IP target", () => {
  it(
    "IP target emits no DEP0123 warning",
    async () => {
      const spy = vi.spyOn(process, "emitWarning")
      const { cert, key } = await makeSelfSigned()
      server = tls.createServer({ cert, key }, (socket) => socket.end()).listen(0, "127.0.0.1")
      await new Promise<void>((resolve) => server?.once("listening", () => resolve()))
      const address = server.address() as AddressInfo
      await tlsHandshake({ hostname: "127.0.0.1", ip: "127.0.0.1", port: address.port }, ctx)
      const messages = spy.mock.calls.map((call) => String(call[0]))
      expect(messages.some((message) => message.includes("RFC 6066"))).toBe(false)
      spy.mockRestore()
    },
    15000,
  )
})
