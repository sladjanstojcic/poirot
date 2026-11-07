import fc from "fast-check"
import { describe, expect, it } from "vitest"
import { computeHash } from "../../src/synthesis/change-hash.js"

function shuffleKeys<T extends Record<string, unknown>>(obj: T, seed: number): T {
  const entries = Object.entries(obj)
  let s = seed >>> 0
  const rnd = () => ((s = (s * 1103515245 + 12345) >>> 0) / 0x100000000)
  for (let i = entries.length - 1; i > 0; i--) {
    const j = Math.floor(rnd() * (i + 1))
    ;[entries[i], entries[j]] = [entries[j]!, entries[i]!]
  }
  return Object.fromEntries(entries) as T
}

describe("computeHash properties", () => {
  it("is invariant under top-level key reordering", () => {
    const alertableArb = fc.dictionary(
      fc.stringMatching(/^[a-z][a-z0-9_.]{0,32}$/),
      fc.oneof(fc.string({ maxLength: 64 }), fc.integer(), fc.boolean(), fc.constant(null)),
      { maxKeys: 20 },
    )
    fc.assert(
      fc.property(alertableArb, fc.integer({ min: 1, max: 1_000_000 }), (obj, seed) => {
        const hashA = computeHash(obj)
        const hashB = computeHash(shuffleKeys(obj, seed))
        expect(hashA).toBe(hashB)
      }),
      { numRuns: 200 },
    )
  })

  it("is invariant under set-like array reordering", () => {
    const arrayArb = fc.array(fc.oneof(fc.string({ maxLength: 32 }), fc.integer(), fc.boolean()), { maxLength: 10 })
    fc.assert(
      fc.property(arrayArb, fc.integer({ min: 1, max: 1_000_000 }), (arr, seed) => {
        const shuffled = [...arr]
        let s = seed >>> 0
        const rnd = () => ((s = (s * 1103515245 + 12345) >>> 0) / 0x100000000)
        for (let i = shuffled.length - 1; i > 0; i--) {
          const j = Math.floor(rnd() * (i + 1))
          ;[shuffled[i], shuffled[j]] = [shuffled[j]!, shuffled[i]!]
        }
        expect(computeHash({ san: arr })).toBe(computeHash({ san: shuffled }))
      }),
      { numRuns: 200 },
    )
  })

  it("returns lowercase 64-char hex sha256", () => {
    fc.assert(
      fc.property(fc.dictionary(fc.string({ maxLength: 32 }), fc.string({ maxLength: 64 })), (obj) => {
        expect(computeHash(obj)).toMatch(/^[a-f0-9]{64}$/)
      }),
      { numRuns: 100 },
    )
  })
})
