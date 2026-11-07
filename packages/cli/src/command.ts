import { Command, Option } from "commander"
import packageJson from "../package.json" with { type: "json" }

const csv = (value: string) =>
  value
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean)

const parseIntOr =
  (fallback: number) =>
  (value: string): number => {
    const parsed = Number.parseInt(value, 10)
    return Number.isFinite(parsed) ? parsed : fallback
  }

/** "0.1.0 (node v24.19.0)" or "0.1.0 (bun 1.3.9)" — spec 05 §3.4. */
function versionString(): string {
  const bun = (globalThis as any).Bun?.version as string | undefined
  return `${(packageJson as any).version} (${bun ? `bun ${bun}` : `node ${process.version}`})`
}

export function buildCommand(): Command {
  const program = new Command()
  program
    // Spec 05 §4: usage errors exit 2 (commander defaults to 1); --help/--version exit 0.
    .exitOverride((error) => process.exit(error.exitCode === 0 ? 0 : 2))
    .name("poirot")
    .description("CLI debugger for web requests.")
    .version(versionString(), "-V, --version")
    .argument("[urls...]", "URLs or domains to probe")
    .option("-f, --file <path>", "Read URLs from file, one per line")
    .addOption(
      new Option("-o, --output <mode>", "Output mode")
        .choices(["pretty", "json", "ndjson", "github-actions"])
        .env("POIROT_OUTPUT"),
    )
    .option("-v, --verbose", "Show full per-phase trace")
    .option("-q, --quiet", "Suppress all non-error output")
    .option("--debug", "Dump internals to stderr")
    .option("--no-color", "Disable ANSI color")
    .addOption(
      new Option("--concurrency <n>", "Parallel URL probes").argParser(parseIntOr(10)).default(10).env("POIROT_CONCURRENCY"),
    )
    .option("--rate-limit-ms <n>", "Minimum delay between URL probes", parseIntOr(0))
    .addOption(new Option("--timeout <ms>", "Per-URL timeout").argParser(parseIntOr(10_000)).default(10_000).env("POIROT_TIMEOUT"))
    .addOption(new Option("--user-agent <ua>", "HTTP User-Agent").env("POIROT_USER_AGENT"))
    .option("--ua-preset <name>", "UA preset: chrome|firefox|safari|mobile|googlebot")
    .addOption(new Option("--dns <resolver>", "DNS resolver IP or DoH URL (default: system)").env("POIROT_DNS"))
    .option("--dkim-selectors <list>", "Comma-separated DKIM selectors", csv)
    .option("--probe-smtp", "Dial SMTP port 25 on MX hosts")
    .option("--fail-on <codes>", "Comma-separated Issue.code values", csv)
    .option("--fail-on-grade <grade>", "Fail when grade is worse than <grade>")
    .option("--list-codes", "Print every Issue.code with severity and meaning")

  return program
}
