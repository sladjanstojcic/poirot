import { performance } from "node:perf_hooks"
import { describe, expect, it } from "vitest"
import { subresource } from "../../../src/probes/phase3/subresource.js"

const ctx = {
  traceStart: performance.now(),
  signal: new AbortController().signal,
  flags: {},
  cache: new Map(),
  logger: () => {},
}

describe("subresource", () => {
  it("extracts scripts + flags mixed content", async () => {
    const body = Buffer.from(`<html><head>
      <script src="https://ex.test/a.js"></script>
      <script src="http://ex.test/b.js"></script>
      <script src="https://cdn.test/c.js" integrity="sha256-abc"></script>
    </head></html>`)
    const r = await subresource(
      {
        body,
        body_truncated: false,
        base_url: "https://ex.test/",
        content_type: "text/html",
      },
      ctx,
    )
    expect(r.data?.resources?.length).toBe(3)
    expect(r.data?.mixed_content_count).toBe(1)
    expect(r.data?.sri_missing_count).toBe(1)
  })

  it("skipped for non-HTML", async () => {
    const r = await subresource(
      {
        body: Buffer.from(""),
        body_truncated: false,
        base_url: "https://ex.test/",
        content_type: "image/png",
      },
      ctx,
    )
    expect(r.status).toBe("skipped")
  })
})
