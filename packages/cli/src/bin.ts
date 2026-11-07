#!/usr/bin/env node
import { ISSUE_CODES, UA_PRESETS, probe, type Trace } from "@poirot/core"
import net from "node:net"
import process from "node:process"
import { buildCommand } from "./command.js"
import { EXIT, traceExitCode } from "./exit-code.js"
import { collectIssues } from "./issues.js"
import { readUrls } from "./input/urls.js"
import { renderGithubActions } from "./renderer/github-actions.js"
import { renderJson } from "./renderer/json.js"
import { renderNdjson } from "./renderer/ndjson.js"
import { renderPretty } from "./renderer/pretty.js"

type OutputMode = "pretty" | "json" | "ndjson" | "github-actions"
type Grade = "A+" | "A" | "B" | "C" | "D" | "F"

const GRADE_RANK: Record<Grade, number> = { "A+": 6, A: 5, B: 4, C: 3, D: 2, F: 1 }

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/** One line per registered code: CODE  severity  message (sorted by code). */
function formatIssueCodes(): string {
  const entries = Object.entries(ISSUE_CODES).sort(([a], [b]) => a.localeCompare(b))
  const width = Math.max(...entries.map(([code]) => code.length))
  return entries.map(([code, meta]) => `${code.padEnd(width)}  ${meta.severity.padEnd(4)}  ${meta.message}`).join("\n")
}

async function main(): Promise<number> {
  process.on("SIGINT", () => process.exit(EXIT.SIGINT))
  const program = buildCommand()
  program.parse(process.argv)
  const opts = program.opts() as Record<string, any>

  if (opts.listCodes) {
    process.stdout.write(`${formatIssueCodes()}\n`)
    return EXIT.OK
  }

  if (opts.debug) process.env.DEBUG = process.env.DEBUG ? `${process.env.DEBUG},poirot:*` : "poirot:*"
  if (opts.color === false) process.env.NO_COLOR = "1"

  if (opts.uaPreset) {
    if (!(opts.uaPreset in UA_PRESETS)) {
      process.stderr.write(`poirot: unknown --ua-preset "${opts.uaPreset}". Valid: ${Object.keys(UA_PRESETS).join(", ")}\n`)
      process.exit(EXIT.USAGE)
    }
    if (!opts.userAgent) opts.userAgent = UA_PRESETS[opts.uaPreset as keyof typeof UA_PRESETS]
  }

  if (opts.dns && !net.isIP(opts.dns) && !/^https:\/\//i.test(opts.dns)) {
    process.stderr.write("poirot: --dns must be an IP address or https:// DoH URL\n")
    process.exit(EXIT.USAGE)
  }

  // stdin is read only on demand: with no URL arguments, or when "-" is given.
  // Reading it unconditionally hangs whenever stdin is an open pipe (cron, ssh, CI).
  const positional = program.args.filter((arg) => arg !== "-")
  const wantsStdin = program.args.includes("-") || (positional.length === 0 && !opts.file)
  const { urls, invalid } = await readUrls({
    positional,
    file: opts.file,
    stdin: wantsStdin && !process.stdin.isTTY ? process.stdin : null,
  })
  for (const token of invalid) process.stderr.write(`poirot: skipping invalid URL "${token}"\n`)
  if (!urls.length) {
    if (!invalid.length) program.outputHelp({ error: true })
    process.exit(EXIT.USAGE)
  }

  if (opts.failOn) {
    const unknown = (opts.failOn as string[]).filter((code) => !(code in ISSUE_CODES))
    if (unknown.length) {
      process.stderr.write(`poirot: unknown codes: ${unknown.join(", ")}\n`)
      process.exit(EXIT.USAGE)
    }
  }

  if (opts.failOnGrade && !(opts.failOnGrade in GRADE_RANK)) {
    process.stderr.write(`poirot: --fail-on-grade must be one of ${Object.keys(GRADE_RANK).join(", ")}\n`)
    process.exit(EXIT.USAGE)
  }

  const mode: OutputMode = (opts.output as OutputMode) ?? (process.stdout.isTTY ? "pretty" : "json")
  const concurrency = Math.max(1, Number(opts.concurrency ?? 10))
  const timeout = Math.max(1, Number(opts.timeout ?? 10_000))
  const rateLimitMs = Math.max(0, Number(opts.rateLimitMs ?? 0))

  const traces = new Array<Trace | null>(urls.length).fill(null)
  let cursor = 0
  let nextAllowed = 0
  let hadProbeError = false

  const workers = Array.from({ length: Math.min(concurrency, urls.length) }, async () => {
    while (true) {
      const idx = cursor
      cursor += 1
      if (idx >= urls.length) return

      if (rateLimitMs > 0) {
        const wait = nextAllowed - Date.now()
        if (wait > 0) await sleep(wait)
        nextAllowed = Math.max(nextAllowed, Date.now()) + rateLimitMs
      }

      const target = urls[idx]!
      try {
        traces[idx] = await probe(target, {
          timeout,
          dns: opts.dns,
          userAgent: opts.userAgent,
          probeSmtp: !!opts.probeSmtp,
          dkimSelectors: opts.dkimSelectors,
        })
      } catch (error) {
        hadProbeError = true
        process.stderr.write(`poirot: ${target}: ${(error as Error).message}\n`)
      }
    }
  })

  await Promise.all(workers)
  const completed = traces.filter((trace): trace is Trace => trace != null)

  if (!opts.quiet) {
    if (mode === "json") {
      const payload = completed.length === 1 ? completed[0]! : completed
      process.stdout.write(`${renderJson(payload as any)}\n`)
    } else if (mode === "ndjson") {
      for (const trace of completed) process.stdout.write(`${renderNdjson(trace)}\n`)
    } else if (mode === "github-actions") {
      for (const trace of completed) {
        const out = renderGithubActions(trace)
        if (out) process.stdout.write(`${out}\n`)
      }
    } else {
      for (const trace of completed) process.stdout.write(`${renderPretty(trace, { verbose: !!opts.verbose })}\n\n`)
    }
  }

  // Bulk rule (spec 05 §4): the maximum of every per-URL code.
  let exitCode = Math.max(hadProbeError ? EXIT.GATE : EXIT.OK, ...completed.map(traceExitCode))
  if (opts.failOn) {
    const failCodes = new Set(opts.failOn as string[])
    const matched = completed.some((trace) => collectIssues(trace).some((issue) => failCodes.has(issue.code)))
    if (matched) exitCode = Math.max(exitCode, EXIT.GATE)
  }
  if (opts.failOnGrade) {
    const threshold = GRADE_RANK[opts.failOnGrade as Grade]
    const matched = completed.some((trace) => GRADE_RANK[trace.synthesis.grade] < threshold)
    if (matched) exitCode = Math.max(exitCode, EXIT.GATE)
  }

  return exitCode
}

/** Resolves once everything written to `stream` so far has been flushed. */
const flushed = (stream: NodeJS.WriteStream) => new Promise<void>((resolve) => stream.write("", () => resolve()))

// Exit explicitly once output is flushed: libraries can leave requests in flight
// after the deadline (e.g. DNS lookups under Bun) that would keep the process alive.
main().then(async (code) => {
  await Promise.all([flushed(process.stdout), flushed(process.stderr)])
  process.exit(code)
}).catch((error) => {
  process.stderr.write(`poirot: ${(error as Error).message}\n`)
  process.exit(1)
})
