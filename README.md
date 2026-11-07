<div align="center">

# Poirot

**A traceroute for web requests.**

Give Poirot a URL and it walks every step of the request — DNS, TCP, TLS, HTTP, redirects — then audits what came back, in one readable trace.

[![CI](https://github.com/sladjanstojcic/poirot/actions/workflows/test.yml/badge.svg)](https://github.com/sladjanstojcic/poirot/actions/workflows/test.yml)
[![Release](https://img.shields.io/github/v/release/sladjanstojcic/poirot)](https://github.com/sladjanstojcic/poirot/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macOS%20%7C%20windows-lightgrey)

</div>

---

Debugging a misbehaving site usually means stitching together `dig`, `curl -v`, `openssl s_client` and a few web checkers. Poirot runs those steps for you, over IPv4 and IPv6, and reports where the request went, how long each step took, and what is wrong — as a terminal report or as JSON for your pipelines.

```text
◆ poirot v0.1.0  ·  example.com → https://example.com/
────────────────────────────────────────────────────────────

  Domain
    Registrar      RESERVED-Internet Assigned Numbers Authority (created 1995-08-14, age 31y)
    Expires        2027-08-13  ✓ 278d left
    DNSSEC         not signed
    Nameservers    hera.ns.cloudflare.com, elliott.ns.cloudflare.com
    Email stack    not checked (domain does not send or receive mail)
                   MX: null (RFC 7505) — domain rejects mail

  Request 1    GET https://example.com/    200 OK    542ms
    ├─ dns      4ms   via system  104.20.23.154 (v4)
    ├─ tcp     11ms   104.20.23.154:443
    ├─ tls    427ms   TLS 1.3  TLS_AES_256_GCM_SHA384  ALPN h2
    │                 cert Cloudflare TLS Issuing ECC CA 3
    │                 expires 2026-12-25 (48d)  fp sha256 85CA:6AB0:…:F07A
    └─ http    54ms   h2  577 B  text/html  server: cloudflare

    Stacks
      v4: 93ms   104.20.23.154        h2   200
      v6: fail   TCP_UNREACHABLE
      – only v4 answered (v6 failure is informational)

    Audits
      Headers        HSTS ✗  CSP ✗  X-Frame ⚠  XCTO ⚠  (5 more)
      Cookies        (none set)
      Subresources   none · 0 mixed-content · 0 without SRI
      Hosting        AS13335 CLOUDFLARENET - Cloudflare, Inc., US · CDN Cloudflare
      security.txt   ✗ not present
      HTTP/3         advertised (Alt-Svc)

  Verdict  warn  ·  Grade  F  (30/100)  ·  5 issues
    ⚠  DNSSEC_UNSIGNED_ANSWER          DNSKEY present but no RRSIG observed
    ⚠  HSTS_MISSING                    No Strict-Transport-Security header
    ⚠  CSP_MISSING                     No Content-Security-Policy header
    ⚠  CLICKJACKING_NOT_PREVENTED      No X-Frame-Options and no CSP frame-ancestors
    ⚠  X_CONTENT_TYPE_OPTIONS_MISSING  Missing X-Content-Type-Options: nosniff

  Total 553 ms · schemaVersion 1.0 · algorithm v2
```

## Contents

- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [What Poirot checks](#what-poirot-checks)
- [Using Poirot in CI](#using-poirot-in-ci)
- [Reference](#reference)
- [Known limitations](#known-limitations)
- [Responsible use](#responsible-use)
- [Development](#development)
- [License](#license)

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/sladjanstojcic/poirot/main/install/install.sh | sh
```

The installer downloads a single self-contained binary to `~/.local/bin/poirot` and verifies its SHA-256 checksum. Binaries are published for Linux (x64, arm64), macOS (x64, arm64) and Windows (x64, via Git Bash for the script). No runtime is required.

| Variable | Effect |
|---|---|
| `POIROT_INSTALL_DIR` | Install directory instead of `~/.local/bin` |
| `POIROT_VERSION` | Release tag to install instead of the latest, e.g. `v0.1.0` |
| `POIROT_VERIFY_SIGSTORE=1` | Also verify the Sigstore signature (requires `cosign`) |

You can also download a binary from [Releases](https://github.com/sladjanstojcic/poirot/releases) and place it on your `PATH`. Every release binary is signed with Sigstore and carries a SLSA build-provenance attestation:

```bash
gh attestation verify poirot-linux-x64 --owner sladjanstojcic
```

## Usage

```bash
poirot example.com                                   # full trace, pretty output
poirot example.com -v                                # expanded: headers, SANs, subresources, curl commands
poirot example.com --output json > trace.json        # machine-readable trace
poirot --file domains.txt --output ndjson            # many URLs, one JSON object per line
poirot http://localhost:3000                         # local and intranet hosts work too
poirot example.com --dns https://cloudflare-dns.com/dns-query   # resolve over DNS-over-HTTPS
```

- A bare domain is probed over HTTPS (`example.com` → `https://example.com/`). Pass `http://` explicitly for plain HTTP.
- URLs come from arguments, `--file` (one per line, `#` comments allowed) or stdin. stdin is read when no URL argument is given, or when `-` is one of the arguments: `cat urls.txt | poirot - extra.com`. Tokens that are not URLs are skipped with a warning.
- Output is pretty when stdout is a terminal and JSON when piped; `--output pretty|json|ndjson|github-actions` forces a mode.
- Without `--dns`, the address to connect to is resolved the way your system does it (hosts file, VPN, split DNS), like `curl`. DNS record checks query `1.1.1.1`. `--dns` sets one resolver for both: an IP address or a DNS-over-HTTPS URL.

Run `poirot --help` for every flag and `poirot --list-codes` for every issue code.

## Examples

**Get the verdict as data.** Every run produces the same JSON trace, so `jq` can pull out whatever you need:

```console
$ poirot example.com -o json | jq '.synthesis | {verdict, grade, score}'
{
  "verdict": "warn",
  "grade": "F",
  "score": 30
}
```

**Follow a redirect chain.** Each hop is a separate request in the trace:

```console
$ poirot http://github.com -o json | jq -r '.requests[] | "\(.response.status)  \(.url)"'
301  http://github.com/
200  https://github.com/
```

**Check when a certificate expires:**

```console
$ poirot github.com -o json | jq '.requests[-1].attempts.v4.tls.data.cert_leaf | {issuer, days_to_expiry}'
{
  "issuer": "C=GB O=Sectigo Limited CN=Sectigo Public Server Authentication CA DV E36",
  "days_to_expiry": 81
}
```

**Audit many domains at once.** NDJSON gives one trace per line; URLs run in parallel (`--concurrency`, default 10):

```console
$ printf "example.com\ngithub.com\nexpired.badssl.com\n" > domains.txt
$ poirot --file domains.txt -o ndjson | jq -r '[.input.raw, .synthesis.grade, .synthesis.verdict] | @tsv' | column -t
example.com         F  warn
github.com          B  warn
expired.badssl.com  F  fail
```

**Fail a script on a specific problem.** Exit codes tell you what happened without parsing anything:

```console
$ poirot expired.badssl.com --fail-on CERT_EXPIRED -q; echo "exit $?"
exit 1
$ poirot this-does-not-exist.example.com -q; echo "exit $?"
exit 3
```

**Annotate a pull request.** `--output github-actions` prints workflow commands that GitHub shows inline:

```console
$ poirot expired.badssl.com --output github-actions
::warning title=SPF_MISSING::warn  No SPF record  (expired.badssl.com)
::warning title=DMARC_MISSING::warn  No DMARC record  (expired.badssl.com)
::error title=CERT_EXPIRED::fail  Cert expired 4227d ago  (expired.badssl.com)
…
```

**Debug your own server.** `localhost` and intranet names resolve through your system, and `-v` adds every response header, the certificate SANs and a `curl` command that reproduces each attempt:

```console
$ poirot http://localhost:3000 -v
```

## What Poirot checks

| Area | Checks |
|---|---|
| **Domain** | Registration and expiry (RDAP), nameservers, DNS records (A, AAAA, CNAME, MX, TXT, NS, CAA, SOA, HTTPS), DNSSEC signals |
| **Email** | SPF (including lookup limits), DMARC, DKIM, BIMI, MTA-STS, null MX |
| **Network** | Separate IPv4 and IPv6 attempts with per-step timings: DNS, TCP connect, TLS handshake, HTTP exchange |
| **TLS** | Protocol, cipher, ALPN, key exchange, certificate chain, expiry, hostname match, trust, OCSP, CAA vs issuer |
| **HTTP** | Status, redirect chain with downgrade and loop detection, response body handling |
| **Security headers** | HSTS (and preload status), CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP, version disclosure |
| **Content** | Cookies (Secure, HttpOnly, SameSite, prefix rules), subresources, mixed content, Subresource Integrity |
| **Hosting** | ASN, CDN and WAF fingerprint, `/.well-known/security.txt`, HTTP/3 advertisement |

Each finding is an issue with a stable code, a severity (`fail`, `warn`, `info`) and a message. The letter grade follows the [MDN HTTP Observatory](https://developer.mozilla.org/en-US/observatory) scoring, so missing HSTS, CSP, X-Frame-Options and X-Content-Type-Options alone bring a site to F. The JSON trace includes a deterministic `change_hash` for comparing runs.

## Using Poirot in CI

Gate a pipeline on specific findings or on the grade, and get inline annotations in GitHub Actions:

```yaml
- name: Install Poirot
  run: |
    curl -fsSL https://raw.githubusercontent.com/sladjanstojcic/poirot/main/install/install.sh | sh
    echo "$HOME/.local/bin" >> "$GITHUB_PATH"

- name: Check production
  run: poirot https://example.com --output github-actions --fail-on CERT_EXPIRED,CERT_EXPIRING_30D --fail-on-grade C
```

`--fail-on` exits 1 when any listed issue code appears; `--fail-on-grade C` exits 1 when the grade is worse than C.

## Reference

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Every URL got a response, and no `--fail-on` / `--fail-on-grade` gate matched |
| `1` | A gate matched, or a probe crashed |
| `2` | Usage error: bad flag or value, or no valid URL |
| `3` | DNS: the host does not resolve |
| `4` | TLS: every handshake failed |
| `5` | Network: connection refused, unreachable or reset |
| `6` | Timeout: `--timeout` was reached before a response |
| `130` | Interrupted (Ctrl-C) |

With several URLs the highest code wins. Certificate problems on a site that still answers (expired, untrusted, wrong name) are findings, not exit codes; gate on them with `--fail-on CERT_EXPIRED,CERT_UNTRUSTED,CERT_NAME_MISMATCH`.

### Environment variables

| Variable | Default for |
|---|---|
| `POIROT_OUTPUT` | `--output` |
| `POIROT_DNS` | `--dns` |
| `POIROT_TIMEOUT` | `--timeout` in ms (default `10000`) |
| `POIROT_USER_AGENT` | `--user-agent` |
| `POIROT_CONCURRENCY` | `--concurrency` (default `10`) |
| `NO_COLOR` / `FORCE_COLOR` | Disable / force ANSI colors |

Command-line flags take precedence over environment variables.

## Known limitations

- HTTP/3 is detected from `Alt-Svc` and DNS HTTPS records only; Poirot does not open a QUIC connection.
- DNSSEC is detection only (signed or not), not full chain validation.
- DKIM is checked against a built-in list of about 40 common selectors; pass yours with `--dkim-selectors`.
- OCSP revocation checks are best effort and are skipped when the responder is unreachable.
- RDAP coverage depends on the registry: some ccTLDs (for example `.de`) have no public RDAP service, reported as `RDAP_UNREACHABLE`.
- Port 25 checks (`--probe-smtp`) are usually blocked from cloud and home networks.
- The Windows binary is built and tested in CI but has not been tested by hand.

## Responsible use

> **Only run Poirot against systems you own or are explicitly authorized to test.**

Poirot is a read-only diagnostic tool: it performs DNS lookups, TCP connections, TLS handshakes and HTTP GET requests against the target. It does not bypass authentication, enumerate hidden resources or exploit vulnerabilities. Automated use against third-party domains can still violate terms of service or computer-misuse laws (CFAA in the US, CMA in the UK, and similar elsewhere). Poirot ignores `robots.txt` — it is a debugger, not a crawler — and leaves the request rate to you.

## Development

Requires Node.js 24 and pnpm 10. Release binaries are built with Bun.

```bash
pnpm install
pnpm test          # unit and end-to-end tests
pnpm test:live     # tests against real public hosts
pnpm typecheck
pnpm dev example.com
```

The repository is a pnpm workspace: `packages/core` holds the probes and the trace model, `packages/cli` the command line and renderers.

## License

[MIT](./LICENSE)
