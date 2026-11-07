// Refresh bundled CDN / cloud provider IP ranges.
// Run manually or via the weekly workflow in Step 7.
//
// Sources (all public, no auth):
//   Cloudflare: https://www.cloudflare.com/ips-v4  /  /ips-v6
//   AWS:        https://ip-ranges.amazonaws.com/ip-ranges.json
//   Fastly:     https://api.fastly.com/public-ip-list
//   GCP:        https://www.gstatic.com/ipranges/cloud.json
import fs from "node:fs/promises"
import path from "node:path"

const OUT = path.resolve("packages/core/src/data/ip-ranges")

async function fetchText(url: string): Promise<string> {
  const response = await fetch(url)
  if (!response.ok) throw new Error(`${url} → HTTP ${response.status}`)
  return response.text()
}

async function fetchJson(url: string): Promise<unknown> {
  const response = await fetch(url)
  if (!response.ok) throw new Error(`${url} → HTTP ${response.status}`)
  return response.json()
}

async function main() {
  await fs.mkdir(OUT, { recursive: true })
  const jobs: Array<[string, () => Promise<unknown>]> = [
    [
      "cloudflare.json",
      async () => ({
        v4: (await fetchText("https://www.cloudflare.com/ips-v4")).trim().split("\n"),
        v6: (await fetchText("https://www.cloudflare.com/ips-v6")).trim().split("\n"),
      }),
    ],
    ["aws.json", async () => fetchJson("https://ip-ranges.amazonaws.com/ip-ranges.json")],
    ["fastly.json", async () => fetchJson("https://api.fastly.com/public-ip-list")],
    ["gcp.json", async () => fetchJson("https://www.gstatic.com/ipranges/cloud.json")],
  ]
  for (const [file, fn] of jobs) {
    try {
      const data = await fn()
      await fs.writeFile(path.join(OUT, file), `${JSON.stringify(data, null, 2)}\n`)
      console.log(`✓ ${file}`)
    } catch (error) {
      console.warn(`⚠ ${file}: ${(error as Error).message}`)
    }
  }
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
