import { describe, expect, it } from "vitest"

describe("smoke", () => {
  it("imports @poirot/core without crashing", async () => {
    const mod = await import("../src/index.js")
    expect(mod).toBeDefined()
  })
})
