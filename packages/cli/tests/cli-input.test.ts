import { describe, expect, it } from "vitest"
import { runCli, startServer } from "./helpers/run-cli.js"

describe("CLI input handling", () => {
  it("does not read stdin when a URL is given", async () => {
    const server = await startServer()
    const r = await runCli([server.url, "-o", "json"], { stdin: "pipe-open", killAfterMs: 10_000 })
    await server.close()
    expect(r.timedOut).toBe(false)
    expect(r.code).toBe(0)
  }, 15_000)

  it('reads stdin with "-"', async () => {
    const server = await startServer()
    const r = await runCli(["-", "-o", "ndjson"], { stdin: `${server.url}\n` })
    await server.close()
    const lines = r.stdout.trim().split("\n")
    expect(lines).toHaveLength(1)
    expect(JSON.parse(lines[0]!).input.url).toBe(server.url)
  }, 15_000)

  it("invalid token warns on stderr and stdout stays valid JSON", async () => {
    const server = await startServer()
    const r = await runCli([server.url, "ht!tp:://??", "-o", "json"])
    await server.close()
    expect(r.code).toBe(0)
    expect(JSON.parse(r.stdout).input.url).toBe(server.url)
    expect(r.stderr).toContain('skipping invalid URL "ht!tp:://??"')
  }, 15_000)

  it("only invalid tokens → exit 2", async () => {
    const r = await runCli(["ht!tp:://??", "-o", "json"])
    expect(r.code).toBe(2)
    expect(r.stdout).toBe("")
  }, 15_000)

  it("--dns garbage → exit 2", async () => {
    const r = await runCli(["example.com", "--dns", "notaresolver"])
    expect(r.code).toBe(2)
    expect(r.stderr).toContain("--dns must be an IP address or https:// DoH URL")
  }, 15_000)

  it("--dns accepts an IP and a DoH URL (validation only)", async () => {
    const server = await startServer()
    const r1 = await runCli([server.url, "--dns", "1.1.1.1", "-q"])
    const r2 = await runCli([server.url, "--dns", "https://cloudflare-dns.com/dns-query", "-q"])
    await server.close()
    expect(r1.code).not.toBe(2)
    expect(r2.code).not.toBe(2)
  }, 30_000)
})
