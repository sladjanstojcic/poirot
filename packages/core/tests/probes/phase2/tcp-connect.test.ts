import net from "node:net"
import { performance } from "node:perf_hooks"
import { afterEach, describe, expect, it } from "vitest"
import { tcpConnect } from "../../../src/probes/phase2/tcp-connect.js"

const ctx = {
  traceStart: performance.now(),
  signal: new AbortController().signal,
  flags: {},
  cache: new Map(),
  logger: () => {},
}

let server: net.Server | null = null

afterEach(() => {
  if (server) server.close()
})

describe("tcpConnect", () => {
  it("connects to a listening port", async () => {
    server = net.createServer().listen(0, "127.0.0.1")
    await new Promise<void>((resolve) => server?.once("listening", () => resolve()))
    const address = server.address()
    const port = typeof address === "object" && address ? address.port : 0
    const r = await tcpConnect({ ip: "127.0.0.1", port }, ctx)
    expect(r.status).toBe("pass")
    expect(r.data?.connected).toBe(true)
    expect(r.data?.connect_ms).toBeGreaterThanOrEqual(0)
  })

  it("emits TCP_REFUSED on closed port", async () => {
    const r = await tcpConnect({ ip: "127.0.0.1", port: 1 }, ctx)
    expect(r.status).toBe("fail")
    expect(r.issues.map((issue) => issue.code)).toContain("TCP_REFUSED")
  })
})
