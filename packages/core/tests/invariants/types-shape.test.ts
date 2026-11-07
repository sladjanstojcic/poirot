import { describe, expect, expectTypeOf, it } from "vitest"
import type {
  Trace,
  RequestTrace,
  NetworkAttempt,
  HttpResponse,
  DomainContext,
  Issue,
  Synthesis,
  Timing,
  ProbeResult,
  ProbeStatus,
} from "../../src/types/index.js"

describe("types round-trip", () => {
  it("Trace serializes and parses deep-equal", () => {
    const t: Trace = {
      schemaVersion: "1.0",
      traceStartedAt: "2026-04-18T10:00:00.000Z",
      duration_ms: 162,
      input: {
        raw: "example.com",
        url: "https://example.com/",
        userAgent: "poirot/0.1.0",
        flags: {},
      },
      runner: {
        name: "poirot",
        version: "0.1.0",
        runtime: "node",
        runtime_version: "v22.14.0",
      },
      domain: {
        domain: "example.com",
        rdap: {
          status: "pass",
          data: { registrar: "ICANN" },
          issues: [],
          timing: { startedAt_ms: 0, duration_ms: 10 },
          alertable_fields: ["registrar"],
        },
        dns: {
          status: "pass",
          data: {
            resolver: "1.1.1.1",
            a: ["1.2.3.4"],
            aaaa: [],
            mx: [],
            txt: [],
            ns: [],
            caa: [],
            dnssec: {
              signed: false,
              rrsig_present: false,
              ds_present_at_parent: false,
              dnskey_present: false,
            },
            queries_made: 0,
            total_ms: 0,
          },
          issues: [],
          timing: { startedAt_ms: 0, duration_ms: 10 },
          alertable_fields: [],
        },
        email: {
          status: "pass",
          data: { null_mx: false, dkim: {}, mx: [] },
          issues: [],
          timing: { startedAt_ms: 0, duration_ms: 10 },
          alertable_fields: [],
        },
      },
      requests: [],
      synthesis: {
        verdict: "pass",
        grade: "A",
        score: 95,
        worst_issues: [],
        timings: {
          total_ms: 162,
          by_phase: {
            hostname_context_ms: 10,
            network_ms: 0,
            audits_ms: 0,
            synthesis_ms: 0,
          },
        },
        change_hash: "abc",
        change_fields: [],
        audit_algorithm_version: 2,
      },
    }

    const round = JSON.parse(JSON.stringify(t))
    expect(round).toEqual(t)
  })
})
