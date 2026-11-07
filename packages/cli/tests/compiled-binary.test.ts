import { afterAll, beforeAll, describe, expect, it } from "vitest"
import { spawn, spawnSync } from "node:child_process"
import http from "node:http"
import os from "node:os"
import path from "node:path"

// Release binaries are built with `bun build --compile`. Bun swaps some npm
// packages (notably `undici`) for built-in shims, so the Node test suite alone
// cannot prove the shipped binary works. This test builds and runs it.
const bunAvailable = spawnSync("bun", ["--version"]).status === 0
const binPath = path.join(os.tmpdir(), `poirot-test-bin-${process.pid}${process.platform === "win32" ? ".exe" : ""}`)

function run(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const cp = spawn(binPath, args, { stdio: ["ignore", "pipe", "pipe"] })
    let stdout = ""
    let stderr = ""
    cp.stdout.on("data", (d) => (stdout += d.toString()))
    cp.stderr.on("data", (d) => (stderr += d.toString()))
    cp.on("close", (code) => resolve({ code: code ?? 0, stdout, stderr }))
  })
}

describe.skipIf(!bunAvailable)("compiled binary", () => {
  let server: http.Server

  beforeAll(async () => {
    const build = spawnSync("bun", ["build", "./src/bin.ts", "--compile", `--outfile=${binPath}`], {
      cwd: path.resolve("."),
      encoding: "utf8",
    })
    if (build.status !== 0) throw new Error(`bun build failed: ${build.stderr}`)
    server = http.createServer((_req, res) => {
      res.writeHead(200)
      res.end("ok")
    })
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()))
  }, 60_000)

  afterAll(() => new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve())))

  it("compiled binary probes a local HTTP server", async () => {
    const port = (server.address() as any).port
    const r = await run([`http://127.0.0.1:${port}/`, "--output", "json"])
    expect(r.stdout).not.toContain("PROBE_THREW")
    expect(r.code).toBe(0)
    expect(JSON.parse(r.stdout).requests[0].response.status).toBe(200)
  }, 30_000)
})
