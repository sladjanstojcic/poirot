import { afterEach, describe, expect, it } from "vitest"
import http from "node:http"
import { probe } from "../../src/orchestrator/probe.js"

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

describe("orchestrator.probe()", () => {
  it(
    "produces a Trace with all required fields",
    async () => {
      server = http
        .createServer((_req, res) => {
          res.writeHead(200, { "content-type": "text/html" })
          res.end("<html><body>hi</body></html>")
        })
        .listen(0, "127.0.0.1")
      await new Promise<void>((resolve) => server?.once("listening", () => resolve()))
      const port = (server.address() as any).port

      const t = await probe(`http://127.0.0.1:${port}/`, { timeout: 5000 })
      expect(t.schemaVersion).toBe("1.0")
      expect(t.input.url).toBe(`http://127.0.0.1:${port}/`)
      expect(t.synthesis.change_hash).toMatch(/^[a-f0-9]{64}$/)
      expect(typeof t.synthesis.grade).toBe("string")
    },
    15000,
  )

  it(
    "deadline while waiting for headers reports HTTP_TIMEOUT",
    async () => {
      server = http.createServer(() => {}).listen(0, "127.0.0.1")
      await new Promise<void>((resolve) => server?.once("listening", () => resolve()))
      const port = (server.address() as any).port
      const t = await probe(`http://127.0.0.1:${port}/`, { timeout: 1000 })
      const all = JSON.stringify(t)
      expect(t.requests[0]!.attempts.v4!.http.issues[0]!.code).toBe("HTTP_TIMEOUT")
      expect(all).not.toContain('"aborted"')
    },
    15000,
  )

  it(
    "probe returns within timeout + 1500 ms when body never ends",
    async () => {
      server = http
        .createServer((_req, res) => {
          res.writeHead(200, { "content-type": "text/html" })
          res.write("<html>")
        })
        .listen(0, "127.0.0.1")
      await new Promise<void>((resolve) => server?.once("listening", () => resolve()))
      const port = (server.address() as any).port
      const t0 = Date.now()
      await probe(`http://127.0.0.1:${port}/`, { timeout: 1000 })
      expect(Date.now() - t0).toBeLessThan(2500)
      server.closeAllConnections()
    },
    15000,
  )

  it(
    "no ref'd Timeout survives probe()",
    async () => {
      server = http
        .createServer((_req, res) => {
          res.writeHead(200, { "content-type": "text/html" })
          res.end("<html><body>hi</body></html>")
        })
        .listen(0, "127.0.0.1")
      await new Promise<void>((resolve) => server?.once("listening", () => resolve()))
      const port = (server.address() as any).port
      const timers = () => process.getActiveResourcesInfo().filter((r) => r === "Timeout").length
      const before = timers()
      await probe(`http://127.0.0.1:${port}/`, { timeout: 30_000 })
      await new Promise((resolve) => setTimeout(resolve, 50))
      expect(timers()).toBeLessThanOrEqual(before)
    },
    15000,
  )

  it(
    "stalled body keeps the response and reports HTTP_TIMEOUT",
    async () => {
      server = http
        .createServer((_req, res) => {
          res.writeHead(200, { "content-type": "text/event-stream" })
          res.write("data: hi\n\n")
        })
        .listen(0, "127.0.0.1")
      await new Promise<void>((resolve) => server?.once("listening", () => resolve()))
      const port = (server.address() as any).port
      const t = await probe(`http://127.0.0.1:${port}/`, { timeout: 1000 })
      server.closeAllConnections()
      expect(t.requests[0]!.response?.status).toBe(200)
      expect(t.requests[0]!.attempts.v4!.http.issues.some((issue) => issue.code === "HTTP_TIMEOUT")).toBe(true)
    },
    15000,
  )

  it(
    "localhost skips phase 1",
    async () => {
      server = http
        .createServer((_req, res) => {
          res.writeHead(200).end("ok")
        })
        .listen(0, "127.0.0.1")
      await new Promise<void>((resolve) => server?.once("listening", () => resolve()))
      const port = (server.address() as any).port
      const t = await probe(`http://localhost:${port}/`, { timeout: 5000 })
      expect(t.domain.rdap.status).toBe("skipped")
      expect(t.domain.dns.status).toBe("skipped")
      expect(t.domain.email.status).toBe("skipped")
      expect(t.requests[0]!.response?.status).toBe(200)
    },
    15000,
  )

  it(
    "refused port produces no header audit issues",
    async () => {
      const t = await probe("http://127.0.0.1:1/", { timeout: 5000 })
      const codes = JSON.stringify(t)
      for (const code of ["HSTS_MISSING", "CSP_MISSING", "CLICKJACKING_NOT_PREVENTED", "X_CONTENT_TYPE_OPTIONS_MISSING", "SECURITYTXT_MISSING", "HOSTING_UNKNOWN"]) {
        expect(codes).not.toContain(`"${code}"`)
      }
      expect(t.requests[0]!.audits.headers.status).toBe("skipped")
      expect(t.requests[0]!.audits.headers.skipped?.reason).toBe("upstream_failed")
    },
    15000,
  )

  it(
    "no response on final hop → F/0/fail",
    async () => {
      const t = await probe("http://127.0.0.1:1/", { timeout: 5000 })
      expect(t.synthesis.grade).toBe("F")
      expect(t.synthesis.score).toBe(0)
      expect(t.synthesis.verdict).toBe("fail")
    },
    15000,
  )

  it(
    "subresource audit sees the page body",
    async () => {
      server = http
        .createServer((_req, res) => {
          res.writeHead(200, { "content-type": "text/html" })
          res.end('<html><head><script src="https://cdn.example/app.js"></script><link rel="stylesheet" href="/site.css"></head><body><img src="/logo.png"></body></html>')
        })
        .listen(0, "127.0.0.1")
      await new Promise<void>((resolve) => server?.once("listening", () => resolve()))
      const port = (server.address() as any).port
      const t = await probe(`http://127.0.0.1:${port}/`, { timeout: 5000 })
      const sub = t.requests[0]!.audits.subresources.data!
      expect(sub.resources.map((r) => r.tag).sort()).toEqual(["img", "link", "script"])
      expect(sub.counts_by_type.script).toBe(1)
      expect(JSON.stringify(t)).not.toContain("rawBody")
    },
    15000,
  )

  it(
    "default User-Agent sent on the wire matches the trace",
    async () => {
      let sent = ""
      server = http
        .createServer((req, res) => {
          if (req.url === "/") sent = String(req.headers["user-agent"])
          res.writeHead(200).end("ok")
        })
        .listen(0, "127.0.0.1")
      await new Promise<void>((resolve) => server?.once("listening", () => resolve()))
      const port = (server.address() as any).port
      const t = await probe(`http://127.0.0.1:${port}/`, { timeout: 5000 })
      expect(sent).toBe(t.input.userAgent)
      expect(sent).toMatch(/^poirot\/0\.1\.1 /)
    },
    15000,
  )
})
