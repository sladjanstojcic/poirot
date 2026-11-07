import { describe, expect, it } from "vitest"
import { detectRedirectLoop, nextHopUrl } from "../../src/orchestrator/redirect-follow.js"

describe("redirect-follow", () => {
  it("returns absolute URL for relative Location", () => {
    const n = nextHopUrl("https://ex.test/a", 302, [["location", "/b"]])
    expect(n).toBe("https://ex.test/b")
  })

  it("returns null on terminal status", () => {
    expect(nextHopUrl("https://ex.test/", 200, [])).toBeNull()
  })

  it("detects loop", () => {
    expect(detectRedirectLoop(["https://ex.test/a", "https://ex.test/b"], "https://ex.test/a")).toBe(true)
    expect(detectRedirectLoop(["https://ex.test/a"], "https://ex.test/b")).toBe(false)
  })
})
