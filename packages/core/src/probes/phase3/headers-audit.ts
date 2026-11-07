import { defineProbe } from "../../probe.js"
import { ISSUE } from "../../issues/codes.js"
import type { HeadersAudit, Issue, ProbeStatus } from "../../types/index.js"
import { hstsPreloadStatus } from "./hsts-preload.js"

type H = Array<[string, string]>

const getAll = (h: H, name: string) => h.filter(([k]) => k.toLowerCase() === name.toLowerCase()).map(([, v]) => v)
const get = (h: H, name: string) => getAll(h, name)[0]

export interface HeadersAuditInput {
  headers: H
  url: string
}

export const headersAudit = defineProbe<HeadersAuditInput, HeadersAudit>(
  "headersAudit",
  [
    "hsts.status",
    "csp.status",
    "x_frame_options.status",
    "x_content_type_options.status",
    "referrer_policy.status",
    "permissions_policy.status",
    "coop.status",
    "coep.status",
    "corp.status",
    "server_leak.status",
  ],
  async (input, ctx) => {
    const h = input.headers
    const issues: Issue[] = []
    const u = new URL(input.url)

    // HSTS
    const hstsRaw = get(h, "strict-transport-security")
    const hsts: HeadersAudit["hsts"] = { status: "fail" as ProbeStatus }
    if (!hstsRaw) {
      issues.push({ severity: "warn", code: ISSUE.HSTS_MISSING, message: "No Strict-Transport-Security header" })
    } else {
      const hstsValues = getAll(h, "strict-transport-security")
      const m = /max-age=(\d+)/i.exec(hstsRaw)
      const max_age = m ? +m[1]! : 0
      const include_subdomains = /includesubdomains/i.test(hstsRaw)
      const preload = /preload/i.test(hstsRaw)
      const pre = await hstsPreloadStatus(u.hostname, ctx.signal)
      const preload_listed = pre === "preloaded"
      let st: ProbeStatus = "pass"
      if (hstsValues.length > 1) {
        issues.push({ severity: "info", code: ISSUE.HSTS_MULTIPLE, message: "Multiple HSTS headers present" })
      }
      if (!max_age || max_age < 2592000) {
        issues.push({ severity: "fail", code: ISSUE.HSTS_VERY_WEAK_MAX_AGE, message: `HSTS max-age=${max_age}` })
        st = "fail"
      } else if (max_age < 31536000) {
        issues.push({ severity: "warn", code: ISSUE.HSTS_WEAK_MAX_AGE, message: `HSTS max-age=${max_age}` })
        st = "warn"
      }
      if (preload && !preload_listed) {
        issues.push({ severity: "info", code: ISSUE.HSTS_PRELOAD_MISSING, message: "preload directive but domain not in Chromium list" })
      }
      if (preload_listed) {
        issues.push({ severity: "info", code: ISSUE.HSTS_PRELOAD_ELIGIBLE, message: "Domain is in Chromium HSTS preload list" })
      }
      Object.assign(hsts, { value: hstsRaw, max_age, include_subdomains, preload, preload_listed, status: st })
    }

    const csp = getAll(h, "content-security-policy").join(", ") || undefined
    const cspAudit: HeadersAudit["csp"] = { status: "fail" as ProbeStatus }
    if (!csp) {
      issues.push({ severity: "warn", code: ISSUE.CSP_MISSING, message: "No Content-Security-Policy header" })
    } else {
      cspAudit.value = csp
      cspAudit.status = "pass"
      const directives = new Set(csp.split(";").map((part) => part.trim().split(/\s+/, 1)[0]?.toLowerCase()).filter(Boolean))
      if (/unsafe-inline/i.test(csp)) {
        issues.push({ severity: "warn", code: ISSUE.CSP_UNSAFE_INLINE, message: "CSP contains 'unsafe-inline'" })
        cspAudit.status = "warn"
      }
      if (/unsafe-eval/i.test(csp)) {
        issues.push({ severity: "warn", code: ISSUE.CSP_UNSAFE_EVAL, message: "CSP contains 'unsafe-eval'" })
        cspAudit.status = "warn"
      }
      if (!directives.has("base-uri")) {
        issues.push({ severity: "warn", code: ISSUE.CSP_BASE_URI_MISSING, message: "CSP lacks base-uri directive" })
        cspAudit.status = "warn"
      }
      if (!directives.has("form-action")) {
        issues.push({ severity: "warn", code: ISSUE.CSP_FORM_ACTION_MISSING, message: "CSP lacks form-action directive" })
        cspAudit.status = "warn"
      }
    }

    const xfo = get(h, "x-frame-options")
    const xcto = get(h, "x-content-type-options")
    if (!xfo && !/frame-ancestors/i.test(csp ?? "")) {
      issues.push({ severity: "warn", code: ISSUE.CLICKJACKING_NOT_PREVENTED, message: "No X-Frame-Options and no CSP frame-ancestors" })
    }
    if (!xcto || xcto.toLowerCase() !== "nosniff") {
      issues.push({ severity: "warn", code: ISSUE.X_CONTENT_TYPE_OPTIONS_MISSING, message: "Missing X-Content-Type-Options: nosniff" })
    }
    const referrer = get(h, "referrer-policy")
    if (!referrer) {
      issues.push({ severity: "info", code: ISSUE.REFERRER_POLICY_MISSING, message: "No Referrer-Policy header" })
    } else if (referrer.toLowerCase() === "unsafe-url") {
      issues.push({ severity: "warn", code: ISSUE.REFERRER_POLICY_UNSAFE_URL, message: "Referrer-Policy is unsafe-url" })
    }

    const server = get(h, "server")
    const xpb = get(h, "x-powered-by")
    if (server && /\d/.test(server)) {
      issues.push({ severity: "info", code: ISSUE.SERVER_VERSION_LEAK, message: `Server: ${server}` })
    }
    if (xpb) {
      issues.push({ severity: "info", code: ISSUE.X_POWERED_BY_LEAK, message: `X-Powered-By: ${xpb}` })
    }

    const data: HeadersAudit = {
      hsts,
      csp: cspAudit,
      x_frame_options: { value: xfo, status: xfo ? "pass" : "warn" },
      x_content_type_options: { value: xcto, status: xcto?.toLowerCase() === "nosniff" ? "pass" : "warn" },
      referrer_policy: { value: referrer, status: !referrer || referrer.toLowerCase() === "unsafe-url" ? "warn" : "pass" },
      permissions_policy: { value: get(h, "permissions-policy"), status: get(h, "permissions-policy") ? "pass" : "warn" },
      coop: { value: get(h, "cross-origin-opener-policy"), status: get(h, "cross-origin-opener-policy") ? "pass" : "warn" },
      coep: { value: get(h, "cross-origin-embedder-policy"), status: get(h, "cross-origin-embedder-policy") ? "pass" : "warn" },
      corp: { value: get(h, "cross-origin-resource-policy"), status: get(h, "cross-origin-resource-policy") ? "pass" : "warn" },
      server_leak: { server, x_powered_by: xpb, status: server && /\d/.test(server) ? "warn" : "pass" },
      early_hints_seen: false,
    }

    const status: ProbeStatus = issues.some((i) => i.severity === "fail")
      ? "fail"
      : issues.some((i) => i.severity === "warn")
        ? "warn"
        : "pass"
    return { status, data, issues }
  },
)
