import { dnsRecords } from "../probes/phase1/dns-records.js"
import { emailStack } from "../probes/phase1/email-stack.js"
import { rdap } from "../probes/phase1/rdap.js"
import type { ProbeCtx } from "../probe.js"
import type { DomainContext, EmailStackResult, ProbeResult } from "../types/index.js"

function skippedResult<T>(reason: "upstream_failed"): ProbeResult<T> {
  return { status: "skipped", issues: [], timing: { startedAt_ms: 0, duration_ms: 0 }, skipped: { reason }, alertable_fields: [] }
}

export interface Phase1Input {
  domain: string
  /** eTLD+1 of `domain` (www.example.co.uk → example.co.uk); RDAP only knows registered names. */
  registrableDomain: string
  /** Time limit for the whole phase (ms). Phase 1 never holds up the request. */
  budgetMs?: number
  dnsResolver?: string
  dkimSelectors: string[]
}

/** Domain context (RDAP, records, email) gets at most this long by default. */
export const PHASE1_BUDGET_MS = 5000

const RESOLVER_FAILURES = new Set(["DNS_TIMEOUT", "DNS_UNREACHABLE"])

export async function runPhase1(input: Phase1Input, parent: ProbeCtx): Promise<DomainContext> {
  // A plain controller + timer (not AbortSignal.any/timeout): the event loop holds
  // the timer, so the budget fires even when nothing else references the signal.
  const budget = new AbortController()
  const timer = setTimeout(() => budget.abort(new Error("POIROT_PHASE1_BUDGET")), input.budgetMs ?? PHASE1_BUDGET_MS)
  const onParentAbort = () => budget.abort(parent.signal.reason)
  if (parent.signal.aborted) onParentAbort()
  else parent.signal.addEventListener("abort", onParentAbort, { once: true })
  try {
    return await runWithin(input, { ...parent, signal: budget.signal })
  } finally {
    clearTimeout(timer)
    parent.signal.removeEventListener("abort", onParentAbort)
  }
}

async function runWithin(input: Phase1Input, ctx: ProbeCtx): Promise<DomainContext> {
  const [rdapResult, dnsResult] = await Promise.all([
    rdap({ domain: input.registrableDomain }, ctx),
    dnsRecords({ domain: input.domain, resolver: input.dnsResolver }, ctx),
  ])

  // A name that does not exist has no mail setup to audit.
  const nxdomain = dnsResult.issues.some((issue) => issue.code === "DNS_NXDOMAIN")
  // The record resolver did not answer at all: email lookups would fail the same way.
  const resolverDown =
    !dnsResult.data?.a.length && !dnsResult.data?.aaaa.length && dnsResult.issues.some((issue) => RESOLVER_FAILURES.has(issue.code))
  const emailResult = nxdomain || resolverDown
    ? skippedResult<EmailStackResult>("upstream_failed")
    : await emailStack(
        {
          domain: input.domain,
          dns: dnsResult.data!,
          dkim_selectors: input.dkimSelectors,
          resolver: input.dnsResolver,
        },
        ctx,
      )

  return {
    domain: input.domain,
    rdap: rdapResult,
    dns: dnsResult,
    email: emailResult,
  }
}
