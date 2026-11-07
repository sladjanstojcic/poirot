import { afterEach, describe, expect, it } from "vitest"
import http from "node:http"
import { probe } from "../../src/index.js"

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

describe("Trace invariants", () => {
  it(
    "round-trips through JSON without loss",
    async () => {
      server = http
        .createServer((_req, res) => {
          res.writeHead(200)
          res.end("x")
        })
        .listen(0, "127.0.0.1")
      await new Promise<void>((resolve) => server?.once("listening", () => resolve()))
      const port = (server.address() as any).port
      const t = await probe(`http://127.0.0.1:${port}/`, { timeout: 5000 })
      const round = JSON.parse(JSON.stringify(t))
      expect(round).toEqual(t)
    },
    15000,
  )
})
