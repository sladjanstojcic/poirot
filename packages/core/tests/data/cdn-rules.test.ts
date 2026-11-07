import { describe, expect, it } from "vitest"
import { CDN_RULES, detectCdn, WAF_RULES } from "../../src/data/cdn-rules.js"

describe("cdn/waf rules", () => {
  it("has rules for major CDNs", () => {
    const names = new Set(CDN_RULES.map((rule) => rule.name))
    for (const name of ["Cloudflare", "Fastly", "CloudFront", "Vercel", "Netlify", "Bunny.net"]) {
      expect(names.has(name)).toBe(true)
    }
  })

  it("detectCdn matches Cloudflare via cf-ray header", () => {
    const headers: Array<[string, string]> = [
      ["cf-ray", "abc"],
      ["server", "cloudflare"],
    ]
    expect(detectCdn(headers)).toEqual({ detected: true, name: "Cloudflare" })
  })

  it("detectCdn returns not-detected for a vanilla nginx", () => {
    const headers: Array<[string, string]> = [["server", "nginx/1.25"]]
    expect(detectCdn(headers)).toEqual({ detected: false })
  })
})
