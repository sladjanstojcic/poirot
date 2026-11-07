import { performance } from "node:perf_hooks"
import { DEFAULT_USER_AGENT } from "../version.js"
import { runStack } from "./run-stack.js"
import type { NetworkAttempt } from "../types/index.js"

const STACK_GRACE_MS = 2000

export async function dualStack(args: {
  url: string
  opts: { timeout?: number; dns?: string; userAgent?: string }
  ctx?: any
}): Promise<{ v4?: NetworkAttempt; v6?: NetworkAttempt; primary: "v4" | "v6" | "none"; raw?: Buffer }> {
  const u = new URL(args.url)
  const port = u.port ? Number(u.port) : u.protocol === "https:" ? 443 : 80
  const path = `${u.pathname}${u.search}` || "/"
  const ctx = args.ctx ?? {
    traceStart: performance.now(),
    signal: new AbortController().signal,
    flags: args.opts,
    cache: new Map(),
    logger: () => {},
  }
  const userAgent = args.opts.userAgent ?? DEFAULT_USER_AGENT
  const common = {
    hostname: u.hostname,
    path,
    port,
    isHttps: u.protocol === "https:",
    ctx,
    userAgent,
    resolver: args.opts.dns,
    timeout: args.opts.timeout,
  }

  // Happy-Eyeballs-style grace: once one stack has a response, the other gets
  // STACK_GRACE_MS more, so a blackholed IPv6 route cannot eat the whole deadline.
  const controllers = { v4: new AbortController(), v6: new AbortController() }
  let graceTimer: ReturnType<typeof setTimeout> | undefined
  const run = (stack: "v4" | "v6") =>
    runStack({ ...common, stack, ctx: { ...ctx, signal: AbortSignal.any([ctx.signal, controllers[stack].signal]) } })
      .catch(() => undefined)
      .then((attempt) => {
        if (attempt?.http?.data && !graceTimer) {
          const other = stack === "v4" ? "v6" : "v4"
          graceTimer = setTimeout(() => controllers[other].abort(new Error("POIROT_STACK_GRACE")), STACK_GRACE_MS)
        }
        return attempt
      })
  const [v4, v6] = await Promise.all([run("v4"), run("v6")])
  clearTimeout(graceTimer)
  const primary: "v4" | "v6" | "none" = v4?.http?.data ? "v4" : v6?.http?.data ? "v6" : "none"
  return { v4, v6, primary }
}
