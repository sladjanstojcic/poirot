import { describe, expect, it } from "vitest"
import { toALabel } from "../../src/net/idn.js"

describe("toALabel", () => {
  it("passes ASCII through unchanged", () => {
    expect(toALabel("example.com")).toBe("example.com")
    expect(toALabel("sub.example.co.uk")).toBe("sub.example.co.uk")
  })

  it("converts U-label to A-label", () => {
    expect(toALabel("café.fr")).toBe("xn--caf-dma.fr")
    expect(toALabel("bücher.de")).toBe("xn--bcher-kva.de")
  })

  it("lowercases", () => {
    expect(toALabel("EXAMPLE.COM")).toBe("example.com")
  })
})
