import { performance } from "node:perf_hooks"
import http from "node:http"
import { afterEach, describe, expect, it } from "vitest"
import { httpExchange } from "../../../src/probes/phase2/http-exchange.js"

const ctx = {
  traceStart: performance.now(),
  signal: new AbortController().signal,
  flags: {},
  cache: new Map(),
  logger: () => {},
}

let server: http.Server | null = null

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

describe("httpExchange", () => {
  it("fetches a local HTTP server and captures headers + body", async () => {
    server = http
      .createServer((_req, res) => {
        res.writeHead(200, { "content-type": "text/plain", "x-test": "yes" })
        res.end("hello")
      })
      .listen(0, "127.0.0.1")
    await new Promise<void>((resolve) => server?.once("listening", () => resolve()))
    const address = server.address() as any
    const r = await httpExchange(
      {
        url: `http://127.0.0.1:${address.port}/`,
        method: "GET",
        user_agent: "poirot-test/0.0",
        allowH2: false,
      },
      ctx,
    )
    expect(r.status).toBe("pass")
    expect(r.data?.status).toBe(200)
    expect(r.data?.headers.some(([k]) => k === "x-test")).toBe(true)
    expect(r.data?.body.bytes_received).toBe(5)
    expect(r.data?.curl_command).toContain("curl")
    expect(r.data?.curl_command).toContain("127.0.0.1")
  })

  it("truncates body at body_cap_bytes and emits HTTP_BODY_TRUNCATED", async () => {
    server = http
      .createServer((_req, res) => {
        res.writeHead(200, { "content-type": "application/octet-stream" })
        res.end(Buffer.alloc(10_000, 0x41))
      })
      .listen(0, "127.0.0.1")
    await new Promise<void>((resolve) => server?.once("listening", () => resolve()))
    const address = server.address() as any
    const r = await httpExchange(
      {
        url: `http://127.0.0.1:${address.port}/`,
        method: "GET",
        user_agent: "poirot-test/0.0",
        allowH2: false,
        body_cap_bytes: 1024,
      },
      ctx,
    )
    expect(r.data?.body.truncated_at).toBe(1024)
    expect(r.issues.some((issue) => issue.code === "HTTP_BODY_TRUNCATED")).toBe(true)
  })

  it(
    "emits HTTP_TIMEOUT when server hangs",
    async () => {
      server = http.createServer(() => {}).listen(0, "127.0.0.1")
      await new Promise<void>((resolve) => server?.once("listening", () => resolve()))
      const address = server.address() as any
      const r = await httpExchange(
        {
          url: `http://127.0.0.1:${address.port}/`,
          method: "GET",
          user_agent: "poirot-test/0.0",
          allowH2: false,
          timeout_ms: 500,
        },
        ctx,
      )
      expect(r.status).toBe("fail")
      expect(r.issues.some((issue) => issue.code === "HTTP_TIMEOUT" || issue.code === "PROBE_THREW")).toBe(true)
    },
    5000,
  )
})
