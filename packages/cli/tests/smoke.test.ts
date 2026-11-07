import { describe, expect, it } from "vitest"

describe("cli smoke", () => {
  it("bin entrypoint file exists", async () => {
    const fs = await import("node:fs")
    expect(fs.existsSync("src/bin.ts")).toBe(true)
  })
})
