type Headers = Array<[string, string]>

const hdr = (headers: Headers, name: string) =>
  headers.find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1]

export interface Rule {
  name: string
  test: (headers: Headers) => boolean
}

export const CDN_RULES: Rule[] = [
  { name: "Cloudflare", test: (headers) => hdr(headers, "server") === "cloudflare" || !!hdr(headers, "cf-ray") },
  {
    name: "Fastly",
    test: (headers) => /\bFastly\b/.test(hdr(headers, "server") || "") || /^cache-/.test(hdr(headers, "x-served-by") || ""),
  },
  { name: "CloudFront", test: (headers) => !!hdr(headers, "x-amz-cf-id") || /CloudFront/i.test(hdr(headers, "via") || "") },
  { name: "Akamai", test: (headers) => !!hdr(headers, "x-akamai-transformed") },
  { name: "Vercel", test: (headers) => !!hdr(headers, "x-vercel-id") },
  { name: "Netlify", test: (headers) => !!hdr(headers, "x-nf-request-id") },
  { name: "Bunny.net", test: (headers) => /BunnyCDN/i.test(hdr(headers, "server") || "") || !!hdr(headers, "cdn-pullzone") },
  { name: "GitHub Pages", test: (headers) => hdr(headers, "server") === "GitHub.com" },
]

export const WAF_RULES: Rule[] = [
  { name: "Sucuri", test: (headers) => !!hdr(headers, "x-sucuri-id") },
  { name: "Wordfence", test: (headers) => !!hdr(headers, "x-wordfence") },
  { name: "Imperva", test: (headers) => !!hdr(headers, "x-iinfo") },
  { name: "Cloudflare", test: (headers) => !!hdr(headers, "cf-mitigated") },
]

export function detectCdn(headers: Headers): { detected: boolean; name?: string } {
  for (const rule of CDN_RULES) {
    if (rule.test(headers)) return { detected: true, name: rule.name }
  }
  return { detected: false }
}

export function detectWaf(headers: Headers): { detected: boolean; name?: string } {
  for (const rule of WAF_RULES) {
    if (rule.test(headers)) return { detected: true, name: rule.name }
  }
  return { detected: false }
}
