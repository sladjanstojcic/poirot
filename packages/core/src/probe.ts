import { performance } from "node:perf_hooks"
import { ISSUE } from "./issues/codes.js"
import type { Issue, ProbeResult, ProbeStatus } from "./types/index.js"

/**
 * Structured progress events emitted as a probe runs. Downstream consumers
 * (web app SSE, real-time CLI spinner) subscribe by passing `onEvent` in ctx.
 * CLI pretty output ignores events; it waits for the final Trace.
 */
export type ProbeEvent =
  | { type: "probe.start"; name: string; at_ms: number }
  | { type: "probe.end"; name: string; at_ms: number; status: ProbeStatus; duration_ms: number }
  | { type: "phase.start"; phase: "hostname" | "network" | "audits" | "synthesis"; at_ms: number }
  | { type: "phase.end"; phase: "hostname" | "network" | "audits" | "synthesis"; at_ms: number; duration_ms: number }
  | { type: "log"; level: "debug" | "info" | "warn"; message: string; at_ms: number }

export interface ProbeCtx {
  traceStart: number
  signal: AbortSignal
  flags: Record<string, unknown>
  cache: Map<string, unknown>
  logger: (msg: string, level?: "debug" | "info" | "warn") => void
  /** Optional structured event sink — enables web-app streaming without coupling core to a transport. */
  onEvent?: (event: ProbeEvent) => void
}

type ProbeFn<I, O> = (input: I, ctx: ProbeCtx) => Promise<{
  status: ProbeStatus
  data?: O
  issues?: Issue[]
  skipped?: ProbeResult<O>["skipped"]
}>

export function defineProbe<I, O>(
  name: string,
  alertable_fields: string[],
  fn: ProbeFn<I, O>,
): (input: I, ctx: ProbeCtx) => Promise<ProbeResult<O>> {
  return async (input, ctx) => {
    const startedAt_ms = performance.now() - ctx.traceStart
    const t0 = performance.now()
    ctx.onEvent?.({ type: "probe.start", name, at_ms: startedAt_ms })
    try {
      const res = await fn(input, ctx)
      const duration_ms = performance.now() - t0
      ctx.onEvent?.({
        type: "probe.end",
        name,
        at_ms: startedAt_ms + duration_ms,
        status: res.status,
        duration_ms,
      })
      return {
        status: res.status,
        data: res.data,
        issues: res.issues ?? [],
        timing: { startedAt_ms, duration_ms },
        skipped: res.skipped,
        alertable_fields,
      }
    } catch (err) {
      const duration_ms = performance.now() - t0
      ctx.onEvent?.({
        type: "probe.end",
        name,
        at_ms: startedAt_ms + duration_ms,
        status: "fail",
        duration_ms,
      })
      return {
        status: "fail",
        issues: [
          {
            severity: "fail",
            code: ISSUE.PROBE_THREW,
            message: `${name} threw: ${(err as Error).message}`,
          },
        ],
        timing: { startedAt_ms, duration_ms },
        alertable_fields,
      }
    }
  }
}

/** Abort reason used when the per-URL `--timeout` deadline fires. */
export const DEADLINE_REASON = "POIROT_DEADLINE"

/** True when `signal` was aborted by the probe deadline (not an external cancel). */
export function isDeadline(signal: AbortSignal): boolean {
  return signal.aborted && (signal.reason as Error | undefined)?.message === DEADLINE_REASON
}

/**
 * Settle with `promise`, or reject as soon as `signal` aborts. For libraries
 * that take no AbortSignal (mailauth, easy-ocsp), so --timeout stays a hard limit.
 */
export function untilAborted<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(signal.reason ?? new Error("ABORTED"))
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(signal.reason ?? new Error("ABORTED"))
    signal.addEventListener("abort", onAbort, { once: true })
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort)
        resolve(value)
      },
      (error) => {
        signal.removeEventListener("abort", onAbort)
        reject(error)
      },
    )
  })
}
