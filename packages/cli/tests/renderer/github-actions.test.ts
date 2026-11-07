import { describe, expect, it } from "vitest"
import { renderGithubActions } from "../../src/renderer/github-actions.js"

const trace: any = {
  input: { url: "https://ex.test/" },
  domain: { domain: "ex.test", rdap: { issues: [] }, dns: { issues: [] }, email: { issues: [] } },
  requests: [
    {
      attempts: {},
      audits: {
        headers: { issues: [{ severity: "warn", code: "CSP_MISSING", message: "No CSP" }] },
        cookies: { issues: [] },
        subresources: { issues: [] },
        hosting: { issues: [] },
        securityTxt: { issues: [] },
        http3: { issues: [] },
      },
    },
  ],
  synthesis: { worst_issues: [] },
}

describe("renderGithubActions", () => {
  it("emits one workflow-command line per issue", () => {
    const out = renderGithubActions(trace)
    expect(out).toContain("::warning title=CSP_MISSING::")
    expect(out).toContain("ex.test")
  })
})
