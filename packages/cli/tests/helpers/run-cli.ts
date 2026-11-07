import { spawn } from "node:child_process"
import http from "node:http"
import path from "node:path"

export interface RunResult {
  code: number | null
  signal: NodeJS.Signals | null
  stdout: string
  stderr: string
  ms: number
  timedOut: boolean
}

export interface RunOptions {
  /** "ignore" (default): stdin closed. "pipe-open": a pipe that is never written or closed. string: written, then closed. */
  stdin?: "ignore" | "pipe-open" | string
  env?: Record<string, string>
  /** Kill the process after this many ms (default 20 000). */
  killAfterMs?: number
  /** Called once the process has started (e.g. to send it a signal). */
  onSpawn?: (cp: ReturnType<typeof spawn>) => void
}

/**
 * Runs the CLI from source: node + tsx's JS entry. Cross-platform (Windows cannot
 * spawn the npx/tsx shell shims without a shell) and signals reach the CLI process.
 */
export function runCli(args: string[], opts: RunOptions = {}): Promise<RunResult> {
  const stdinMode = opts.stdin ?? "ignore"
  return new Promise((resolve) => {
    const bin = path.resolve("src/bin.ts")
    const tsxCli = path.resolve("../../node_modules/tsx/dist/cli.mjs")
    const t0 = Date.now()
    const cp = spawn(process.execPath, [tsxCli, bin, ...args], {
      stdio: [stdinMode === "ignore" ? "ignore" : "pipe", "pipe", "pipe"],
      cwd: path.resolve("."),
      env: { ...process.env, NO_COLOR: "1", ...opts.env },
    })
    let stdout = ""
    let stderr = ""
    let timedOut = false
    cp.stdout!.on("data", (d) => (stdout += d.toString()))
    cp.stderr!.on("data", (d) => (stderr += d.toString()))
    if (stdinMode !== "ignore" && stdinMode !== "pipe-open") cp.stdin!.end(stdinMode)
    const killer = setTimeout(() => {
      timedOut = true
      cp.kill("SIGKILL")
    }, opts.killAfterMs ?? 20_000)
    opts.onSpawn?.(cp)
    cp.on("close", (code, signal) => {
      clearTimeout(killer)
      cp.stdin?.destroy()
      resolve({ code, signal, stdout, stderr, ms: Date.now() - t0, timedOut })
    })
  })
}

/** Local HTTP server for e2e tests. `handler` defaults to 200 "ok". */
export async function startServer(handler?: http.RequestListener): Promise<{ url: string; close: () => Promise<void> }> {
  const server = http.createServer(
    handler ??
      ((_req, res) => {
        res.writeHead(200)
        res.end("ok")
      }),
  )
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()))
  const port = (server.address() as any).port
  return {
    url: `http://127.0.0.1:${port}/`,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections()
        server.close(() => resolve())
      }),
  }
}
