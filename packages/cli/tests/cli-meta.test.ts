import { readFileSync } from "node:fs"
import { describe, expect, it } from "vitest"
import { runCli, startServer } from "./helpers/run-cli.js"

describe("CLI meta flags and env defaults", () => {
  it("--list-codes lists CERT_EXPIRED and exits 0", async () => {
    const r = await runCli(["--list-codes"])
    expect(r.code).toBe(0)
    expect(r.stdout).toMatch(/^CERT_EXPIRED\s+fail\s+\S/m)
    expect(r.stdout).toMatch(/^HSTS_MISSING\s+warn\s+\S/m)
  }, 20_000)

  it("POIROT_TIMEOUT=1000 applies", async () => {
    const server = await startServer(() => {})
    const r = await runCli([server.url, "-q"], { env: { POIROT_TIMEOUT: "1000" } })
    await server.close()
    expect(r.ms).toBeLessThan(4000)
    expect(r.code).toBe(6)
  }, 20_000)

  it("POIROT_DNS is validated like --dns", async () => {
    const r = await runCli(["example.com"], { env: { POIROT_DNS: "notaresolver" } })
    expect(r.code).toBe(2)
  }, 20_000)

  it("POIROT_USER_AGENT sets the request User-Agent", async () => {
    let seen = ""
    const server = await startServer((req, res) => {
      if (req.url === "/") seen = String(req.headers["user-agent"])
      res.writeHead(200).end("ok")
    })
    await runCli([server.url, "-q"], { env: { POIROT_USER_AGENT: "poirot-test-ua" } })
    await server.close()
    expect(seen).toBe("poirot-test-ua")
  }, 20_000)

  it("--version includes runtime", async () => {
    const r = await runCli(["--version"])
    const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"))
    expect(r.stdout.trim()).toMatch(new RegExp(`^${version.replace(/\./g, "\\.")} \\((node|bun) v?\\d`))
  }, 20_000)

  it("--help shows defaults", async () => {
    const r = await runCli(["--help"])
    expect(r.stdout).toContain("(default: 10000")
    expect(r.stdout).toContain("(default: system")
  }, 20_000)
})
