import fc from "fast-check"
import { describe, expect, it } from "vitest"
import { expandIPv6, reverseIPv6Nibbles } from "../../src/net/team-cymru.js"

describe("expandIPv6 and reverseIPv6Nibbles properties", () => {
  it("expandIPv6 always produces exactly 32 lowercase nibbles", () => {
    fc.assert(
      fc.property(fc.ipV6(), (ip) => {
        const out = expandIPv6(ip)
        expect(out).toMatch(/^[0-9a-f]{32}$/)
      }),
      { numRuns: 300 },
    )
  })

  it("reverseIPv6Nibbles equals reversed expansion with dots removed", () => {
    fc.assert(
      fc.property(fc.ipV6(), (ip) => {
        const expanded = expandIPv6(ip)
        const reversed = reverseIPv6Nibbles(ip).replace(/\./g, "")
        expect(reversed).toBe(expanded.split("").reverse().join(""))
      }),
      { numRuns: 300 },
    )
  })
})
