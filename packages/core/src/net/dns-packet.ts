import dgram from "node:dgram"
import net from "node:net"
import * as dp from "dns-packet"

/** Build a query packet once; reused by UDP + TCP so id + questions stay consistent. */
function buildQuery(name: string, type: dp.RecordType): dp.Packet {
  return {
    type: "query",
    id: Math.floor(Math.random() * 65535),
    flags: dp.RECURSION_DESIRED,
    questions: [{ type, name }],
  }
}

/**
 * RFC 1035 §4.2.1 — always try UDP first; if TC (truncation) bit set, fall back to TCP.
 */
export async function dnsQuery(
  name: string,
  type: dp.RecordType,
  resolver = "1.1.1.1",
  timeoutMs = 3000,
  signal?: AbortSignal,
): Promise<dp.DecodedPacket> {
  const query = buildQuery(name, type)
  if (/^https?:\/\//i.test(resolver)) return dohQuery(query, resolver, timeoutMs, signal)
  const pkt = await udpQuery(query, resolver, timeoutMs, signal)
  // TC bit = 0x0200 (bit 9 of the 16-bit flags word). dns-packet exposes the constant.
  if (((pkt.flags ?? 0) & dp.TRUNCATED_RESPONSE) !== 0) {
    return tcpQuery(query, resolver, timeoutMs, signal)
  }
  return pkt
}

/**
 * DNS-over-HTTPS (RFC 8484): POST the wire-format query. The CLI only accepts
 * https:// URLs; plain http:// is allowed here so tests can use a local server.
 */
export async function dohQuery(
  query: dp.Packet,
  url: string,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<dp.DecodedPacket> {
  const timeout = AbortSignal.timeout(timeoutMs)
  let res: Response
  try {
    res = await fetch(url, {
      method: "POST",
      body: dp.encode(query),
      headers: { "content-type": "application/dns-message", accept: "application/dns-message" },
      signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
    })
  } catch {
    throw new Error(timeout.aborted ? "DNS_TIMEOUT" : signal?.aborted ? "ABORTED" : "DNS_UNREACHABLE")
  }
  if (!res.ok) throw new Error("DNS_UNREACHABLE")
  return dp.decode(Buffer.from(await res.arrayBuffer()))
}

/** UDP DNS query — exported for testability. */
export function udpQuery(
  query: dp.Packet,
  resolver: string,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<dp.DecodedPacket> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new Error("ABORTED"))
    const isV6 = resolver.includes(":")
    const sock = dgram.createSocket(isV6 ? "udp6" : "udp4")
    let settled = false
    const closeSocket = () => {
      try {
        sock.close()
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "ERR_SOCKET_DGRAM_NOT_RUNNING") throw err
      }
    }
    const settle = (fn: typeof resolve | typeof reject, value: dp.DecodedPacket | Error) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      signal?.removeEventListener("abort", onAbort)
      closeSocket()
      fn(value as any)
    }
    const timer = setTimeout(() => {
      settle(reject, new Error("DNS_TIMEOUT"))
    }, timeoutMs)
    const onAbort = () => {
      settle(reject, new Error("ABORTED"))
    }
    signal?.addEventListener("abort", onAbort, { once: true })
    sock.on("message", (msg) => {
      try {
        settle(resolve, dp.decode(msg))
      } catch (err) {
        settle(reject, err as Error)
      }
    })
    sock.on("error", (err) => {
      settle(reject, err)
    })
    sock.send(dp.encode(query), 53, resolver, (err) => {
      if (err) {
        settle(reject, err)
      }
    })
  })
}

/**
 * TCP DNS query (RFC 1035 §4.2.2 — 2-byte length-prefixed framing).
 * `port` defaults to 53; tests override it to point at a local fixture.
 */
export function tcpQuery(
  query: dp.Packet,
  resolver: string,
  timeoutMs: number,
  signal?: AbortSignal,
  port = 53,
): Promise<dp.DecodedPacket> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new Error("ABORTED"))
    const sock = net.createConnection({ host: resolver, port })
    const chunks: Buffer[] = []
    let expected = -1
    let settled = false
    const settle = (fn: typeof resolve | typeof reject, value: dp.DecodedPacket | Error) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      signal?.removeEventListener("abort", onAbort)
      sock.destroy()
      fn(value as any)
    }
    const timer = setTimeout(() => {
      settle(reject, new Error("DNS_TIMEOUT"))
    }, timeoutMs)
    const onAbort = () => {
      settle(reject, new Error("ABORTED"))
    }
    signal?.addEventListener("abort", onAbort, { once: true })

    sock.once("connect", () => sock.write(dp.streamEncode(query)))
    sock.on("data", (chunk) => {
      chunks.push(chunk)
      const buf = Buffer.concat(chunks)
      if (expected < 0 && buf.length >= 2) expected = buf.readUInt16BE(0) + 2
      if (expected > 0 && buf.length >= expected) {
        try {
          settle(resolve, dp.streamDecode(buf.subarray(0, expected)) as dp.DecodedPacket)
        } catch (err) {
          settle(reject, err as Error)
        }
      }
    })
    sock.on("error", (err) => {
      settle(reject, err)
    })
  })
}
