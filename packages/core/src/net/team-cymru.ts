import ipaddr from "ipaddr.js"
import { dnsQuery } from "./dns-packet.js"

export function reverseIPv4(ip: string): string {
  return ip.split(".").reverse().join(".")
}

/**
 * Expand an IPv6 address to 32 lowercase hex nibbles (no colons).
 * Delegates to `ipaddr.js` — handles `::` compression AND IPv4-mapped
 * notation (`::ffff:192.0.2.1`) correctly, which the previous hand-rolled
 * split/join did not.
 */
export function expandIPv6(ip: string): string {
  return ipaddr.IPv6.parse(ip)
    .toByteArray()
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
}

/** RFC 3596 reverse-pointer form: 32 nibbles in reverse order, dot-separated. */
export function reverseIPv6Nibbles(ip: string): string {
  return expandIPv6(ip).split("").reverse().join(".")
}

export interface AsnInfo {
  asn: number
  cidr: string
  country: string
  rir: string
  date: string
}

function txtPayload(answer: unknown): string | null {
  if (!answer || typeof answer !== "object" || !("data" in answer)) return null
  const data = (answer as { data: unknown }).data
  if (Array.isArray(data)) {
    return data
      .map((chunk) => (Buffer.isBuffer(chunk) ? chunk.toString() : String(chunk)))
      .join("")
  }
  if (Buffer.isBuffer(data)) return data.toString()
  return typeof data === "string" ? data : String(data)
}

export async function teamCymruAsn(ip: string, signal?: AbortSignal): Promise<AsnInfo | null> {
  const name = ip.includes(":")
    ? `${reverseIPv6Nibbles(ip)}.origin6.asn.cymru.com`
    : `${reverseIPv4(ip)}.origin.asn.cymru.com`
  let packet
  try {
    packet = await dnsQuery(name, "TXT", "1.1.1.1", 3000, signal)
  } catch {
    return null
  }
  const textRecord = (packet.answers ?? []).find((answer) => answer.type === "TXT")
  const data = txtPayload(textRecord)
  if (!data) return null
  const parts = data.split(" | ").map((part) => part.trim())
  const asn = Number(parts[0])
  if (!Number.isFinite(asn)) return null
  return {
    asn,
    cidr: parts[1] ?? "",
    country: parts[2] ?? "",
    rir: parts[3] ?? "",
    date: parts[4] ?? "",
  }
}

export async function teamCymruAsnOrg(asn: number, signal?: AbortSignal): Promise<string | null> {
  const name = `AS${asn}.asn.cymru.com`
  let packet
  try {
    packet = await dnsQuery(name, "TXT", "1.1.1.1", 3000, signal)
  } catch {
    return null
  }
  const textRecord = (packet.answers ?? []).find((answer) => answer.type === "TXT")
  const data = txtPayload(textRecord)
  if (!data) return null
  const parts = data.split(" | ").map((part) => part.trim())
  return parts[parts.length - 1] ?? null
}
