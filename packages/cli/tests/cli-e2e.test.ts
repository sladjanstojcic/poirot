import { afterEach, describe, expect, it } from "vitest"
import http from "node:http"
import { runCli } from "./helpers/run-cli.js"

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

describe("CLI end-to-end", () => {
  it(
    "produces JSON output for --output json",
    async () => {
      server = http
        .createServer((_req, res) => {
          res.writeHead(200)
          res.end("ok")
        })
        .listen(0, "127.0.0.1")
      await new Promise<void>((resolve) => server?.once("listening", () => resolve()))
      const port = (server.address() as any).port
      const r = await runCli([`http://127.0.0.1:${port}/`, "--output", "json"])
      expect(r.code).toBe(0)
      const parsed = JSON.parse(r.stdout)
      expect(parsed.schemaVersion).toBe("1.0")
    },
    15000,
  )

  it(
    "exits 1 when --fail-on code matches, and --quiet suppresses stdout",
    async () => {
      server = http
        .createServer((_req, res) => {
          res.writeHead(200)
          res.end("ok")
        })
        .listen(0, "127.0.0.1")
      await new Promise<void>((resolve) => server?.once("listening", () => resolve()))
      const port = (server.address() as any).port
      const r = await runCli([`http://127.0.0.1:${port}/`, "--quiet", "--fail-on", "HSTS_MISSING"])
      expect(r.code).toBe(1)
      expect(r.stdout.trim()).toBe("")
    },
    15000,
  )

  it(
    "rejects unknown --ua-preset with exit 2",
    async () => {
      const r = await runCli(["http://127.0.0.1:1/", "--ua-preset", "bogus"])
      expect(r.code).toBe(2)
      expect(r.stderr).toContain("unknown --ua-preset")
    },
    10000,
  )
})
