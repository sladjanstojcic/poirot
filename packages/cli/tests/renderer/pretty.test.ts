import { describe, expect, it } from "vitest"
import { renderPretty } from "../../src/renderer/pretty.js"
import { FIVE_WARNINGS, redirectTrace, refusedTrace, successTrace } from "./fixtures.js"

const strip = (text: string) => text.replace(/\x1b\[[0-9;]*m/g, "")
const render = (trace: any, verbose = false) => strip(renderPretty(trace, { verbose }))

describe("renderPretty", () => {
  it("verdict is printed once", () => {
    const line = render(successTrace())
      .split("\n")
      .find((l) => l.trim().startsWith("Verdict"))!
    expect(line.match(/warn/gi)).toHaveLength(1)
  })

  it("ms values are integers", () => {
    expect(render(successTrace())).not.toMatch(/\d+\.\d+ ?ms/)
  })

  it("lists every warn/fail issue, not only the worst 3", () => {
    const out = render(successTrace())
    for (const issue of FIVE_WARNINGS) expect(out).toContain(issue.code)
    expect(out).toMatch(/Verdict.*5 issues/)
  })

  it("info issues hidden unless verbose", () => {
    expect(render(successTrace())).not.toContain("REFERRER_POLICY_MISSING")
    expect(render(successTrace(), true)).toContain("REFERRER_POLICY_MISSING")
  })

  it('redirect hop shows "301 → https://…"', () => {
    expect(render(redirectTrace())).toMatch(/301 → https:\/\/www\.ex\.test\//)
  })

  it("skipped audits render as skipped, not FAIL", () => {
    const out = render(refusedTrace())
    const audits = out.slice(out.indexOf("Audits"), out.indexOf("Verdict"))
    expect(audits).toContain("skipped")
    expect(audits).not.toMatch(/FAIL|✗/)
    expect(out).toContain("TCP_REFUSED")
  })

  it("dual-stack consistent line when both stacks succeed", () => {
    const out = render(successTrace())
    expect(out).toMatch(/v4: \d+ms\s+1\.2\.3\.4/)
    expect(out).toMatch(/v6: \d+ms\s+2001:db8::1/)
    expect(out).toContain("dual-stack consistent")
  })

  it("header shows version and input → url", () => {
    expect(render(successTrace())).toMatch(/◆ poirot v0\.1\.0 {2}· {2}ex\.test → https:\/\/ex\.test\//)
  })

  it("matches snapshot", () => {
    expect(render(successTrace())).toMatchSnapshot()
  })

  it("long nameserver lists are capped at 3 and lines fit 100 columns", () => {
    const t: any = successTrace()
    t.domain.dns.data.ns = Array.from({ length: 8 }, (_, i) => `ns-${i}.awsdns-${i}.example-provider.net`)
    const out = render(t)
    expect(out).toMatch(/\(\+[5-7] more\)/)
    expect(Math.max(...out.split("\n").map((l) => l.length))).toBeLessThanOrEqual(100)
  })

  it("zero subresource counts are not listed", () => {
    const t: any = successTrace()
    t.requests[0].audits.subresources.data.counts_by_type = { script: 2, link: 0, img: 0 }
    const line = render(t)
      .split("\n")
      .find((l) => l.includes("Subresources"))!
    expect(line).toContain("2 script")
    expect(line).not.toMatch(/\b0 (link|img)\b/)
  })

  it("no Stacks block when no stack got a response", () => {
    const t: any = refusedTrace()
    t.requests[0].attempts.v6 = t.requests[0].attempts.v4
    expect(render(t)).not.toContain("Stacks")
  })

  it("stages after a failed step say skipped, not no response", () => {
    const out = render(refusedTrace())
    expect(out).toMatch(/├─ tls\s+skipped$/m)
    expect(out).toMatch(/└─ http\s+skipped$/m)
  })

  it("null-MX domain does not show SPF/DMARC as failed (they are not checked)", () => {
    const line = render(successTrace())
      .split("\n")
      .find((l) => l.includes("Email stack"))!
    expect(line).not.toContain("✗")
    expect(line).toContain("not checked")
  })
})

describe("renderPretty --verbose", () => {
  function withSubresources(n: number) {
    const t: any = successTrace()
    t.requests[0].audits.subresources.data.resources = Array.from({ length: n }, (_, i) => ({
      tag: "script",
      url: `https://cdn.ex.test/s${i}.js`,
      origin: "cross",
      mixed_content: false,
      has_integrity: false,
    }))
    return t
  }

  it("verbose lists all response headers", () => {
    const out = render(successTrace(), true)
    expect(out).toMatch(/x-extra: 1/)
    expect(out).toMatch(/content-type: text\/html/)
  })

  it("verbose lists SANs", () => {
    expect(render(successTrace(), true)).toMatch(/SAN\s+ex\.test, www\.ex\.test/)
  })

  it('verbose caps subresources at 50 with "… 10 more"', () => {
    const out = render(withSubresources(60), true)
    expect(out).toContain("https://cdn.ex.test/s49.js")
    expect(out).not.toContain("https://cdn.ex.test/s50.js")
    expect(out).toContain("… 10 more")
  })

  it("verbose lists every audited header with its status", () => {
    const out = render(successTrace(), true)
    expect(out).toMatch(/Referrer-Policy\s+⚠/)
    expect(out).toMatch(/Strict-Transport-Security\s+✓\s+max-age=63072000/)
  })

  it("verbose shows the curl command per attempt", () => {
    expect(render(successTrace(), true)).toContain('curl -2v "https://ex.test/"')
  })

  it("non-verbose output contains none of these", () => {
    const out = render(withSubresources(60))
    for (const text of ["x-extra: 1", "www.ex.test, ", "cdn.ex.test/s1.js", "Referrer-Policy", "curl -2v"]) expect(out).not.toContain(text)
  })

  it("long audited header values are shortened in the audit list", () => {
    const t: any = successTrace()
    const csp = `default-src 'self'; ${"connect-src https://very-long-host.example.com ".repeat(20)}`
    t.requests[0].audits.headers.data.csp.value = csp
    const line = render(t, true)
      .split("\n")
      .find((l) => l.includes("Content-Security-Policy "))!
    expect(line.length).toBeLessThanOrEqual(100)
    expect(line).toContain("…")
  })

  it("informational v6 failure does not warn in the Stacks block", () => {
    const t: any = successTrace()
    const v6 = t.requests[0].attempts.v6
    v6.http = { status: "skipped", issues: [], timing: { startedAt_ms: 0, duration_ms: 0 }, skipped: { reason: "upstream_failed" }, alertable_fields: [] }
    v6.tcp = { status: "fail", issues: [{ severity: "info", code: "TCP_UNREACHABLE", message: "EHOSTUNREACH" }], timing: { startedAt_ms: 0, duration_ms: 0 }, alertable_fields: [] }
    const out = render(t)
    expect(out).not.toContain("dual-stack differs")
    expect(out).toContain("only v4 answered")
  })
})
