import { describe, expect, it } from "vitest"
import { caaCrossCheck, extractOrg, normOrg } from "../../src/synthesis/caa-cross-check.js"

describe("caa-cross-check helpers", () => {
  it("extractOrg handles newline DN separator", () => {
    expect(extractOrg("C=US\nO=Google Trust Services\nCN=WE1")).toBe("google trust services")
  })

  it("normOrg strips inc/llc + punctuation", () => {
    expect(normOrg("DigiCert, Inc.")).toBe("digicert")
  })

  it("passes when cert issuer matches mapping for allowed CA", () => {
    const r = caaCrossCheck(
      [{ flag: 0, tag: "issue", value: "pki.goog" }],
      "C=US\nO=Google Trust Services\nCN=WE1",
    )
    expect(r).toBeNull()
  })

  it("emits CAA_MISMATCH when issuer known but not authorized", () => {
    const r = caaCrossCheck(
      [{ flag: 0, tag: "issue", value: "pki.goog" }],
      "C=US\nO=DigiCert Inc.\nCN=DigiCert Global CA G2",
    )
    expect(r?.code).toBe("CAA_MISMATCH")
  })

  it("emits CAA_FORBIDS_ISSUANCE when CAA is ';' but cert is present", () => {
    const r = caaCrossCheck(
      [{ flag: 0, tag: "issue", value: ";" }],
      "C=US\nO=SomeCA\nCN=x",
    )
    expect(r?.code).toBe("CAA_FORBIDS_ISSUANCE")
  })
})
