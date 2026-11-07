import { findAll } from "domutils"
import { parseDocument } from "htmlparser2"
import { defineProbe } from "../../probe.js"
import { ISSUE } from "../../issues/codes.js"
import type { Issue, SubresourceList } from "../../types/index.js"

export interface SubresourceInput {
  body: Buffer
  body_truncated: boolean
  base_url: string
  content_type?: string
}

const TAG_ATTR = [
  ["script", "src"],
  ["link", "href"],
  ["img", "src"],
  ["iframe", "src"],
  ["source", "src"],
  ["video", "src"],
  ["audio", "src"],
] as const

export const subresource = defineProbe<SubresourceInput, SubresourceList>(
  "subresource",
  ["mixed_content_count", "sri_missing_count", "counts_by_type"],
  async (input) => {
    if (!input.content_type?.includes("text/html")) {
      return { status: "skipped", skipped: { reason: "not_applicable" } }
    }
    const base = new URL(input.base_url)
    const dom = parseDocument(input.body.toString("utf8"))
    const resources: SubresourceList["resources"] = []
    for (const [tag, attr] of TAG_ATTR) {
      const els = findAll((el: any) => el?.name === tag, dom.children) as any[]
      for (const el of els) {
        const a = el.attribs ?? {}
        const raw = a[attr]
        if (!raw) continue
        let url: URL
        try {
          url = new URL(raw, base)
        } catch {
          continue
        }
        resources.push({
          tag: tag as any,
          url: url.toString(),
          origin: url.origin === base.origin ? "same" : "cross",
          mixed_content: base.protocol === "https:" && url.protocol === "http:",
          rel: tag === "link" ? a.rel : undefined,
          as: tag === "link" ? a.as : undefined,
          has_integrity: !!a.integrity,
          integrity: a.integrity,
        })
      }
    }
    const counts_by_type = Object.fromEntries(TAG_ATTR.map(([t]) => [t, 0])) as Record<string, number>
    resources.forEach((r) => {
      counts_by_type[r.tag] = (counts_by_type[r.tag] ?? 0) + 1
    })
    const mixed_content_count = resources.filter((r) => r.mixed_content).length

    const sriApplicable = resources.filter(
      (r) => r.origin === "cross" && (r.tag === "script" || (r.tag === "link" && /stylesheet/i.test(r.rel ?? ""))),
    )
    const sri_missing_count = sriApplicable.filter((r) => !r.has_integrity).length

    const issues: Issue[] = []
    if (mixed_content_count) {
      issues.push({ severity: "warn", code: ISSUE.MIXED_CONTENT_FOUND, message: `${mixed_content_count} mixed-content subresources` })
    }
    if (sri_missing_count) {
      issues.push({ severity: "warn", code: ISSUE.SRI_MISSING_ON_CROSS_ORIGIN, message: `${sri_missing_count} cross-origin subresources without SRI` })
    }
    if (input.body_truncated) {
      issues.push({ severity: "info", code: ISSUE.SUBRESOURCE_BODY_TRUNCATED, message: "Body was truncated; subresource count may be under-reported" })
    }

    const status = issues.some((i) => i.severity === "fail") ? "fail" : issues.length ? "warn" : "pass"
    return {
      status,
      data: {
        resources,
        counts_by_type,
        mixed_content_count,
        sri_missing_count,
        parse_truncated: input.body_truncated,
      },
      issues,
    }
  },
)
