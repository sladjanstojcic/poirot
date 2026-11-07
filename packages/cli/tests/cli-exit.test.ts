import { describe, expect, it } from "vitest"
import { runCli, startServer } from "./helpers/run-cli.js"

describe("CLI exit codes", () => {
  it("refused port exits 5", async () => {
    const r = await runCli(["http://127.0.0.1:1/", "-q"])
    expect(r.code).toBe(5)
  }, 20_000)

  it("invalid --output exits 2", async () => {
    const r = await runCli(["example.com", "-o", "xml"])
    expect(r.code).toBe(2)
  }, 20_000)

  it("--help exits 0", async () => {
    const r = await runCli(["--help"])
    expect(r.code).toBe(0)
    expect(r.stdout).toContain("Usage: poirot")
  }, 20_000)

  it("--version exits 0", async () => {
    const r = await runCli(["--version"])
    expect(r.code).toBe(0)
  }, 20_000)

  it("bulk max: [ok server, refused port] exits 5 and JSON array has 2 traces", async () => {
    const server = await startServer()
    const r = await runCli([server.url, "http://127.0.0.1:1/", "-o", "json"])
    await server.close()
    expect(r.code).toBe(5)
    expect(JSON.parse(r.stdout)).toHaveLength(2)
  }, 20_000)

  // Windows has no POSIX signals; Ctrl-C there is a console event.
  it.skipIf(process.platform === "win32")("SIGINT exits 130", async () => {
    const server = await startServer(() => {})
    const r = await runCli([server.url, "--timeout", "15000", "-q"], {
      onSpawn: (cp) => setTimeout(() => cp.kill("SIGINT"), 1500),
    })
    await server.close()
    expect(r.code).toBe(130)
    expect(r.stderr).not.toMatch(/^\s+at /m)
  }, 20_000)

  it("exits once output is written, even if a library keeps the event loop busy", async () => {
    const server = await startServer()
    const preload = new URL("./fixtures/hold-event-loop.mjs", import.meta.url).href
    const r = await runCli([server.url, "-o", "json"], { env: { NODE_OPTIONS: `--import ${preload}` } })
    await server.close()
    expect(r.code).toBe(0)
    expect(JSON.parse(r.stdout).requests[0].response.status).toBe(200)
    expect(r.ms).toBeLessThan(8000)
  }, 30_000)
})
