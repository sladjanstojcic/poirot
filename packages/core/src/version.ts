import packageJson from "../package.json" with { type: "json" }

export const SCHEMA_VERSION = "1.0" as const
export const AUDIT_ALGORITHM_VERSION = 2 as const

/** User-Agent sent when --user-agent is not given; the trace records the same value. */
export const DEFAULT_USER_AGENT = `poirot/${(packageJson as any).version} (+https://github.com/sladjanstojcic/poirot)`
