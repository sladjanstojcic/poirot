import { performance } from "node:perf_hooks"
import type { AddressInfo } from "node:net"
import tls from "node:tls"
import { describe, expect, it, vi } from "vitest"

vi.mock("easy-ocsp", () => ({ getCertStatus: vi.fn(() => new Promise(() => {})) }))

import { tlsHandshake } from "../../../src/probes/phase2/tls-handshake.js"
import { makeSelfSigned } from "../../fixtures/self-signed-cert.js"

describe("tlsHandshake OCSP", () => {
  it("an OCSP lookup that never settles is bounded by the signal", async () => {
    const { cert, key } = await makeSelfSigned()
    const server = tls.createServer({ cert, key }, (socket) => socket.end()).listen(0, "127.0.0.1")
    await new Promise<void>((resolve) => server.once("listening", () => resolve()))
    const controller = new AbortController()
    setTimeout(() => controller.abort(new Error("POIROT_DEADLINE")), 300)
    const t0 = Date.now()
    const r = await tlsHandshake(
      { hostname: "127.0.0.1", ip: "127.0.0.1", port: (server.address() as AddressInfo).port },
      { traceStart: performance.now(), signal: controller.signal, flags: {}, cache: new Map(), logger: () => {} },
    )
    server.close()
    expect(Date.now() - t0).toBeLessThan(2000)
    expect(r.data?.ocsp.checked).toBe(false)
  }, 10_000)
})
