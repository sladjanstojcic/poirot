import { defineProbe } from "../../probe.js"
import type { RdapResult } from "../../types/index.js"
import { ISSUE } from "../../issues/codes.js"

const IANA_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"

interface Bootstrap {
  services: [string[], string[]][]
}

async function getBase(tld: string, cache: Map<string, unknown>, signal: AbortSignal): Promise<string> {
  let bootstrap = cache.get("rdap:bootstrap") as Bootstrap | undefined
  if (!bootstrap) {
    const response = await fetch(IANA_BOOTSTRAP, { signal })
    if (!response.ok) throw new Error(`IANA_BOOTSTRAP_${response.status}`)
    bootstrap = (await response.json()) as Bootstrap
    cache.set("rdap:bootstrap", bootstrap)
  }
  for (const [tlds, urls] of bootstrap.services) {
    if (tlds.includes(tld) && urls[0]) return urls[0]
  }
  return "https://rdap.org/"
}

function parseDate(value?: string): number | undefined {
  if (!value) return undefined
  const timestamp = new Date(value).getTime()
  return Number.isFinite(timestamp) ? Math.floor(timestamp / 1000) : undefined
}

export const rdap = defineProbe<{ domain: string }, RdapResult>(
  "rdap",
  ["registrar", "expires", "nameservers", "statuses"],
  async ({ domain }, ctx) => {
    if (!domain) {
      return { status: "fail", issues: [{ severity: "fail", code: ISSUE.PROBE_THREW, message: "empty domain" }] }
    }
    const tld = domain.split(".").pop() ?? ""
    let response: Response
    let base = ""
    try {
      base = await getBase(tld, ctx.cache, ctx.signal)
      const url = `${base.replace(/\/$/, "")}/domain/${domain}`
      response = await fetch(url, {
        signal: ctx.signal,
        headers: { accept: "application/rdap+json, application/json" },
      })
    } catch (error) {
      // Registry unreachable or the phase budget ran out: a lookup failure, not a crash.
      const reason = ctx.signal.aborted ? "lookup did not finish in time" : String((error as Error)?.message ?? error)
      return { status: "warn", issues: [{ severity: "warn", code: ISSUE.RDAP_UNREACHABLE, message: `RDAP: ${reason}` }] }
    }
    if (response.status === 404) {
      return {
        status: "warn",
        issues: [{ severity: "warn", code: ISSUE.DOMAIN_UNREGISTERED, message: `${domain} returned 404 from RDAP` }],
      }
    }
    if (!response.ok) {
      return { status: "warn", issues: [{ severity: "warn", code: ISSUE.RDAP_UNREACHABLE, message: `RDAP ${response.status}` }] }
    }

    let body: any
    try {
      body = await response.json()
    } catch {
      return { status: "warn", issues: [{ severity: "warn", code: ISSUE.RDAP_MALFORMED, message: "RDAP response not JSON" }] }
    }

    const registrar = body.entities
      ?.find((entity: any) => (entity.roles || []).includes("registrar"))
      ?.vcardArray?.[1]
      ?.find((field: any[]) => field[0] === "fn")?.[3]

    const events: Record<string, string> = {}
    for (const event of body.events || []) events[event.eventAction] = event.eventDate
    const created = parseDate(events.registration)
    const updated = parseDate(events["last changed"] ?? events["last update"])
    const expires = parseDate(events.expiration)
    const now = Math.floor(Date.now() / 1000)

    const issues: Array<{ severity: "warn" | "fail"; code: string; message: string }> = []
    let status: "pass" | "warn" | "fail" = "pass"
    if (expires) {
      const daysToExpiry = Math.floor((expires - now) / 86400)
      if (daysToExpiry < 0) {
        issues.push({ severity: "warn", code: ISSUE.DOMAIN_EXPIRED, message: `Expired ${-daysToExpiry}d ago` })
        status = "warn"
      } else if (daysToExpiry < 7) {
        issues.push({ severity: "fail", code: ISSUE.DOMAIN_EXPIRING_7D, message: `Expires in ${daysToExpiry}d` })
        status = "fail"
      } else if (daysToExpiry < 30) {
        issues.push({ severity: "warn", code: ISSUE.DOMAIN_EXPIRING_30D, message: `Expires in ${daysToExpiry}d` })
        status = "warn"
      }
    }

    return {
      status,
      data: {
        registrar,
        created,
        updated,
        expires,
        age_days: created ? Math.floor((now - created) / 86400) : undefined,
        days_to_expiry: expires ? Math.floor((expires - now) / 86400) : undefined,
        nameservers: (body.nameservers || []).map((item: any) => String(item.ldhName || "").toLowerCase()).filter(Boolean),
        statuses: body.status || [],
        bootstrap_url: base,
      },
      issues,
    }
  },
)
