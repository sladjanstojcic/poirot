import { describe, expect, it } from "vitest"
import { AUDIT_ALGORITHM_VERSION, SCHEMA_VERSION } from "../../src/version.js"

describe("version constants", () => {
  it("SCHEMA_VERSION is '1.0'", () => {
    expect(SCHEMA_VERSION).toBe("1.0")
  })

  it("AUDIT_ALGORITHM_VERSION is 2 (bumped after stress-test)", () => {
    expect(AUDIT_ALGORITHM_VERSION).toBe(2)
  })
})
