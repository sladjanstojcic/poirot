import fc from "fast-check"
import { describe, expect, it } from "vitest"
import { extractField } from "../../src/probes/phase3/security-txt.js"

describe("security.txt extractField properties", () => {
  it("never throws on arbitrary input", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 4096 }), fc.stringMatching(/^[A-Za-z-]{1,32}$/), (body, field) => {
        extractField(body, field)
      }),
      { numRuns: 500 },
    )
  })

  it("round-trips planted Contact value", () => {
    const email = fc.stringMatching(/^[a-z]{1,16}@[a-z]{1,16}\.[a-z]{2,4}$/)
    const pad = fc.string({ maxLength: 200 }).filter((s) => !/^Contact:/im.test(s))
    fc.assert(
      fc.property(pad, email, pad, (pre, mail, suf) => {
        const body = `${pre}\nContact: mailto:${mail}\n${suf}`
        expect(extractField(body, "Contact")).toBe(`mailto:${mail}`)
      }),
      { numRuns: 100 },
    )
  })

  it("returns undefined when field is absent", () => {
    const body = fc.string({ maxLength: 2000 }).filter((s) => !/^Nonexistent:/im.test(s))
    fc.assert(
      fc.property(body, (s) => {
        expect(extractField(s, "Nonexistent")).toBeUndefined()
      }),
      { numRuns: 200 },
    )
  })
})
