# Changelog

All notable changes to Poirot will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-11-07

### Fixed
- Subresource, mixed-content and SRI audits never received the page body and always reported no subresources.
- The first request's audits no longer wait for the domain checks (RDAP, DNS records, email); a site with slow DNS and a redirect could run out the default timeout and be reported as unreachable.
- The raw response body no longer appears in the JSON trace.
- The User-Agent sent by default now matches the running version (it was always `poirot/0.1.0`).
- Pretty output: IPv4/IPv6 rows stay aligned with long IPv6 addresses; short issuer names show their organisation (`Let's Encrypt YE2`).

## [0.1.0] - 2026-11-07

Initial public release.

### Added
- End-to-end request lifecycle probes: DNS -> TCP -> TLS -> HTTP -> redirects -> audits.
- Domain probes: RDAP, DNS records, and email stack auditing.
- Dual-stack (IPv4 + IPv6) per-hop network attempts.
- TLS analysis including cert chain, OCSP, and key exchange summary.
- CAA vs deployed certificate issuer cross-check.
- Security headers audit with HSTS preload status lookup.
- CSP directive checks (`base-uri`, `form-action`) and referrer policy warnings.
- Cookie audit including secure-cookie-on-http-hop detection across redirects.
- Subresource extraction with SRI warning coverage.
- Hosting fingerprinting via Team Cymru plus bundled CDN/WAF rules.
- HTTP/3 discovery via `Alt-Svc` and HTTPS DNS records.
- `security.txt` probing and canonical validation.
- Deterministic `change_hash` over alertable fields, for comparing runs.
- CLI output modes: `pretty`, `json`, `ndjson`, and `github-actions`; `--verbose` expands pretty output.
- CLI gating flags: `--fail-on` and `--fail-on-grade`.
- Exit codes: 2 usage, 3 DNS, 4 TLS, 5 network, 6 timeout, 130 interrupted; bulk runs exit with the highest code.
- `--list-codes`, and `POIROT_DNS` / `POIROT_TIMEOUT` / `POIROT_USER_AGENT` / `POIROT_CONCURRENCY` defaults.
- Address resolution through the OS resolver (hosts file, VPN, split DNS); `--dns` accepts an IP or a DNS-over-HTTPS URL.
- Bulk input via args, file, and stdin (`-`) with de-duplication; invalid tokens are skipped with a warning.
- Install script for curl-pipe-sh binary installation.

### Distribution
- Single static binaries built via `bun build --compile`.
- Installer support for Linux x64/arm64, macOS x64/arm64, and Windows x64.
- SHA256 verification during install.

### Not included
- Browser (JavaScript) rendering.
- Real QUIC/HTTP/3 connections (discovery only).
- Full DNSSEC chain validation (detection only).
