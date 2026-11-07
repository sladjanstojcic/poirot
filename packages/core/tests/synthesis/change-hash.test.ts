import { describe, expect, it } from "vitest"
import { canonicalize, computeHash } from "../../src/synthesis/change-hash.js"

describe("canonicalize + computeHash", () => {
  it("same content, different key order → same hash", () => {
    const a = { b: 2, a: 1, c: { z: 9, x: 7 } }
    const b = { a: 1, c: { x: 7, z: 9 }, b: 2 }
    expect(computeHash(a)).toBe(computeHash(b))
  })

  it("same set-like array, different order → same hash", () => {
    expect(computeHash({ san: ["b.example", "a.example"] })).toBe(computeHash({ san: ["a.example", "b.example"] }))
  })

  it("different content → different hash", () => {
    expect(computeHash({ a: 1 })).not.toBe(computeHash({ a: 2 }))
  })

  it("canonicalize sorts object keys and set-like arrays", () => {
    expect(canonicalize({ b: 2, a: 1 })).toEqual({ a: 1, b: 2 })
    expect(canonicalize([3, 1, 2])).toEqual([1, 2, 3])
  })
})
