import { describe, expect, it } from "vitest"
import { expandIPv6, reverseIPv4, reverseIPv6Nibbles } from "../../src/net/team-cymru.js"

describe("team-cymru helpers", () => {
  it("reverseIPv4 reverses octets", () => {
    expect(reverseIPv4("172.66.147.243")).toBe("243.147.66.172")
    expect(reverseIPv4("1.1.1.1")).toBe("1.1.1.1")
  })

  it("expandIPv6 expands :: compression", () => {
    expect(expandIPv6("2001:db8::1")).toBe("20010db8000000000000000000000001")
    expect(expandIPv6("::1")).toBe("00000000000000000000000000000001")
    expect(expandIPv6("2606:4700:4700::1111")).toBe("26064700470000000000000000001111")
  })

  // The whole reason we switched from hand-rolled split/join to ipaddr.js:
  // IPv4-mapped v6 addresses (RFC 4291 §2.5.5.2) embed the 32-bit v4 in the low
  // two hextets. 192.0.2.1 → 0xc0 0x00 0x02 0x01 → hextets c000:0201.
  it("expandIPv6 handles IPv4-mapped notation ::ffff:a.b.c.d", () => {
    expect(expandIPv6("::ffff:192.0.2.1")).toBe("00000000000000000000ffffc0000201")
  })

  it("reverseIPv6Nibbles reverses all 32 nibbles", () => {
    // RFC 3596 reverse-pointer form of 2001:db8::1
    expect(reverseIPv6Nibbles("2001:db8::1")).toBe("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2")
  })
})
