import dns from "node:dns"
import { performance } from "node:perf_hooks"
import net from "node:net"
import { ISSUE } from "../../issues/codes.js"
import { dnsQuery } from "../../net/dns-packet.js"
import { defineProbe, isDeadline } from "../../probe.js"
import type { DnsResolve, Issue } from "../../types/index.js"

type Outcome = { answers: string[]; cnames?: string[]; ttl?: number } | { issue: Issue } | "no_answer"

const fail = (code: string, message: string): { issue: Issue } => ({ issue: { severity: "fail", code, message } })

/** Without --dns: resolve like the OS does (/etc/hosts, VPN, split DNS), as curl would. */
async function systemLookup(hostname: string, family: 4 | 6, signal: AbortSignal): Promise<Outcome> {
  let onAbort = () => {}
  const aborted = new Promise<never>((_, reject) => {
    onAbort = () => reject(new Error("ABORTED"))
    if (signal.aborted) onAbort()
    else signal.addEventListener("abort", onAbort, { once: true })
  })
  try {
    const found = await Promise.race([dns.promises.lookup(hostname, { family, all: true }), aborted])
    // getaddrinfo can synthesize IPv4-mapped v6 answers (::ffff:a.b.c.d) when a
    // host has no AAAA record; that is the IPv4 path, not IPv6.
    const answers = found.map((entry) => entry.address).filter((address) => !/^::ffff:/i.test(address))
    return answers.length ? { answers } : "no_answer"
  } catch (error: any) {
    if (error?.message === "ABORTED") return fail(ISSUE.DNS_TIMEOUT, "deadline exceeded")
    if (error?.code === "ENOTFOUND") {
      // glibc reports ENOTFOUND for a missing AAAA (or A) record too. Only call
      // it NXDOMAIN when the name has no address in either family.
      const any = await dns.promises.lookup(hostname, { all: true }).catch(() => [])
      return any.length ? "no_answer" : fail(ISSUE.DNS_NXDOMAIN, `${hostname} does not resolve`)
    }
    if (error?.code === "ENODATA") return "no_answer"
    if (error?.code === "EAI_AGAIN") return fail(ISSUE.DNS_TIMEOUT, "system resolver did not answer")
    return fail(ISSUE.DNS_UNREACHABLE, String(error?.code ?? error?.message ?? "lookup failed"))
  } finally {
    signal.removeEventListener("abort", onAbort)
  }
}

/** With --dns: raw query to the given resolver (IP or DoH URL). */
async function rawLookup(hostname: string, type: "A" | "AAAA", resolver: string, signal: AbortSignal): Promise<Outcome> {
  try {
    const pkt = await dnsQuery(hostname, type as any, resolver, 3000, signal)
    if ((pkt as any).rcode === "NXDOMAIN") return fail(ISSUE.DNS_NXDOMAIN, `${hostname} does not exist (NXDOMAIN)`)
    if ((pkt as any).rcode === "SERVFAIL") return fail(ISSUE.DNS_SERVFAIL, `${resolver} returned SERVFAIL`)
    const answers = (pkt.answers ?? []).filter((answer: any) => answer.type === type).map((answer: any) => answer.data as string)
    if (!answers.length) return "no_answer"
    const cnames = (pkt.answers ?? []).filter((answer: any) => answer.type === "CNAME").map((answer: any) => answer.data as string)
    const ttl = ((pkt.answers ?? []).find((answer: any) => answer.type === type) as any)?.ttl
    return { answers, cnames: cnames.length ? cnames : undefined, ttl }
  } catch (error: any) {
    if (isDeadline(signal) || /DNS_TIMEOUT|ABORTED/.test(String(error?.message))) return fail(ISSUE.DNS_TIMEOUT, `no answer from ${resolver}`)
    return fail(ISSUE.DNS_UNREACHABLE, `${resolver}: ${String(error?.message ?? "unreachable")}`)
  }
}

export interface DnsResolveInput {
  hostname: string
  stack: "v4" | "v6"
  resolver?: string
}

export const dnsResolve = defineProbe<DnsResolveInput, DnsResolve>(
  "dnsResolve",
  ["chosen_ip", "all_answers", "cname_chain"],
  async ({ hostname, stack, resolver }, ctx) => {
    const t0 = performance.now()
    const ipKind = net.isIP(hostname)
    if (ipKind === 4) {
      if (stack === "v6") return { status: "skipped", skipped: { reason: "not_applicable" } }
      return {
        status: "pass",
        data: {
          hostname,
          stack,
          resolver: resolver ?? "system",
          chosen_ip: hostname,
          all_answers: [hostname],
          query_ms: Math.round(performance.now() - t0),
        },
      }
    }
    if (ipKind === 6) {
      if (stack === "v4") return { status: "skipped", skipped: { reason: "not_applicable" } }
      return {
        status: "pass",
        data: {
          hostname,
          stack,
          resolver: resolver ?? "system",
          chosen_ip: hostname,
          all_answers: [hostname],
          query_ms: Math.round(performance.now() - t0),
        },
      }
    }

    const outcome = resolver
      ? await rawLookup(hostname, stack === "v4" ? "A" : "AAAA", resolver, ctx.signal)
      : await systemLookup(hostname, stack === "v4" ? 4 : 6, ctx.signal)
    if (outcome === "no_answer") return { status: "skipped", skipped: { reason: "not_applicable" } }
    if ("issue" in outcome) return { status: "fail", issues: [outcome.issue] }
    return {
      status: "pass",
      data: {
        hostname,
        stack,
        resolver: resolver ?? "system",
        chosen_ip: outcome.answers[0]!,
        all_answers: outcome.answers,
        cname_chain: outcome.cnames,
        ttl: outcome.ttl,
        query_ms: Math.round(performance.now() - t0),
      },
    }
  },
)
