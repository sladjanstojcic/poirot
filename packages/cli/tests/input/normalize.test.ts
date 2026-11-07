import { describe, expect, it } from "vitest"
import { normalizeInputUrl, parseMaybeUrl } from "../../src/input/normalize.js"

describe("normalizeInputUrl", () => {
  it("upgrades bare domain to https", () => {
    expect(normalizeInputUrl("example.com")).toBe("https://example.com/")
  })

  it("preserves existing scheme", () => {
    expect(normalizeInputUrl("http://ex.test")).toBe("http://ex.test/")
  })

  it("parseMaybeUrl returns null for garbage", () => {
    expect(parseMaybeUrl(" not a url ")).toBeNull()
  })
})
