import { afterEach, describe, expect, it } from "vitest"
import https from "node:https"
import { probe } from "../../src/index.js"
import { makeSelfSigned } from "../fixtures/self-signed-cert.js"

let server: https.Server | null = null

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

describe("integration: HTTPS fixture", () => {
  it(
    "exercises the TLS handshake path",
    async () => {
      const { cert, key } = await makeSelfSigned()
      server = https
        .createServer({ cert, key }, (_req, res) => {
          res.writeHead(200, { "content-type": "text/html" })
          res.end("<html></html>")
        })
        .listen(0, "127.0.0.1")
      await new Promise<void>((resolve) => server?.once("listening", () => resolve()))
      const port = (server.address() as any).port

      const t = await probe(`https://127.0.0.1:${port}/`, { timeout: 5000 })
      const tls = t.requests[0]!.attempts.v4!.tls
      expect(tls.data).toBeDefined()
      expect(tls.data!.protocol_version).toMatch(/^1\.(2|3)$/)
      expect(tls.data!.kex).toBeDefined()
      expect(tls.issues.some((i) => i.code === "CERT_UNTRUSTED")).toBe(true)
    },
    15000,
  )
})
