import uaPresets from "./data/ua-presets.json" with { type: "json" }

export { probe, type ProbeOptions } from "./orchestrator/probe.js"
export { defineProbe, type ProbeCtx, type ProbeEvent } from "./probe.js"
export { ISSUE_CODES, type IssueCode } from "./issues/codes.js"
export { AUDIT_ALGORITHM_VERSION, SCHEMA_VERSION } from "./version.js"
export * from "./types/index.js"

export const UA_PRESETS = uaPresets as Record<string, string>
