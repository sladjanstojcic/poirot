import net from "node:net"
import * as dp from "dns-packet"
import { afterEach, describe, expect, it } from "vitest"
import { dnsQuery, tcpQuery, udpQuery } from "../../src/net/dns-packet.js"

let tcpServer: net.Server | null = null

afterEach(
  () =>
    new Promise<void>((resolve) => {
      if (tcpServer) {
        tcpServer.close(() => resolve())
      } else {
        resolve()
      }
    }),
)

describe("dnsQuery", () => {
  it("encodes and decodes a round-trip (helper exists)", () => {
    const buf = dp.encode({
      type: "query",
      id: 1,
      flags: dp.RECURSION_DESIRED,
      questions: [{ type: "A", name: "example.com" }],
    })
    const pkt = dp.decode(buf)
    expect(pkt.questions?.[0]?.name).toBe("example.com")
    expect(typeof dnsQuery).toBe("function")
  })

  it("rejects on abort signal", async () => {
    const ctl = new AbortController()
    ctl.abort()
    await expect(dnsQuery("example.com", "A", "1.1.1.1", 3000, ctl.signal)).rejects.toThrow(/abort|ABORTED/i)
  })

  it("does not close a timed-out UDP socket again when later aborted", async () => {
    const ctl = new AbortController()
    const query = {
      type: "query",
      id: 1,
      flags: dp.RECURSION_DESIRED,
      questions: [{ type: "A", name: "example.com" }],
    } as dp.Packet

    await expect(udpQuery(query, "203.0.113.1", 1, ctl.signal)).rejects.toThrow("DNS_TIMEOUT")
    ctl.abort()
    await new Promise((resolve) => setImmediate(resolve))
  })

  it("tcpQuery reads length-prefixed response from a local TCP fixture", async () => {
    // Stand up a mock TCP DNS server on 127.0.0.1 that always returns a single A answer.
    tcpServer = net.createServer((socket) => {
      const chunks: Buffer[] = []
      socket.on("data", (chunk) => {
        chunks.push(chunk)
        const buf = Buffer.concat(chunks)
        // Wait until we have the full length-prefixed query
        if (buf.length < 2) return
        const qLen = buf.readUInt16BE(0)
        if (buf.length < qLen + 2) return
        // Decode the query to copy its id + echo a canned answer
        const q = dp.streamDecode(buf.subarray(0, qLen + 2))
        const answer = dp.streamEncode({
          type: "response",
          id: q.id ?? 0,
          flags: dp.RECURSION_DESIRED | dp.RECURSION_AVAILABLE,
          questions: q.questions ?? [],
          answers: [{ name: q.questions?.[0]?.name ?? "x", type: "A", class: "IN", ttl: 60, data: "127.0.0.1" }],
        })
        socket.end(answer)
      })
    }).listen(0, "127.0.0.1")
    await new Promise<void>((resolve) => tcpServer?.once("listening", () => resolve()))
    const address = tcpServer.address()
    const port = typeof address === "object" && address ? address.port : 53

    const pkt = await tcpQuery(
      { type: "query", id: 42, flags: dp.RECURSION_DESIRED, questions: [{ type: "A", name: "x.test" }] },
      "127.0.0.1",
      3000,
      undefined,
      port,
    )
    const firstAnswer = pkt.answers?.[0]
    const data = firstAnswer && "data" in firstAnswer ? firstAnswer.data : undefined
    expect(data).toBe("127.0.0.1")
  })

  it("DoH resolver posts wire format and decodes the answer", async () => {
    const http = await import("node:http")
    let contentType = ""
    const server = http.createServer((req, res) => {
      contentType = String(req.headers["content-type"])
      const chunks: Buffer[] = []
      req.on("data", (c) => chunks.push(c))
      req.on("end", () => {
        const query = dp.decode(Buffer.concat(chunks))
        const reply = dp.encode({
          type: "response",
          id: query.id,
          flags: dp.RECURSION_DESIRED,
          questions: query.questions,
          answers: [{ type: "A", name: "example.com", ttl: 60, data: "93.184.215.14" }],
        })
        res.writeHead(200, { "content-type": "application/dns-message" }).end(reply)
      })
    })
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()))
    const url = `http://127.0.0.1:${(server.address() as any).port}/dns-query`
    const pkt = await dnsQuery("example.com", "A", url, 3000)
    server.close()
    expect(contentType).toBe("application/dns-message")
    expect((pkt.answers?.[0] as any)?.data).toBe("93.184.215.14")
  })
})
