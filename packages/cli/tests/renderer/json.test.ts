import { describe, expect, it } from "vitest"
import { renderJson } from "../../src/renderer/json.js"
import { renderNdjson } from "../../src/renderer/ndjson.js"

const trace: any = { schemaVersion: "1.0", input: { url: "x" }, synthesis: { verdict: "pass" } }

describe("renderers", () => {
  it("renderJson emits pretty-printed JSON", () => {
    const out = renderJson(trace)
    expect(JSON.parse(out)).toEqual(trace)
    expect(out).toContain("\n  ")
  })

  it("renderNdjson emits one line", () => {
    const out = renderNdjson(trace)
    expect(out).not.toContain("\n")
    expect(JSON.parse(out)).toEqual(trace)
  })
})
