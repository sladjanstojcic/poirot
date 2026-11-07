import "reflect-metadata"
import { Crypto } from "@peculiar/webcrypto"
import * as x509 from "@peculiar/x509"

x509.cryptoProvider.set(new Crypto())

export async function makeSelfSigned(commonName = "127.0.0.1"): Promise<{ cert: string; key: string }> {
  const alg = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" } as const
  const keys = await x509.cryptoProvider.get().subtle.generateKey(alg, true, ["sign", "verify"])
  const now = new Date()
  const notAfter = new Date(now.getTime() + 24 * 60 * 60 * 1000)
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: `CN=${commonName}`,
    notBefore: now,
    notAfter,
    signingAlgorithm: alg,
    keys,
    extensions: [new x509.SubjectAlternativeNameExtension([{ type: "ip", value: commonName }])],
  })
  const pkcs8 = await x509.cryptoProvider.get().subtle.exportKey("pkcs8", keys.privateKey)
  const keyPem =
    "-----BEGIN PRIVATE KEY-----\n" +
    Buffer.from(pkcs8)
      .toString("base64")
      .replace(/(.{64})/g, "$1\n") +
    "\n-----END PRIVATE KEY-----\n"
  return { cert: cert.toString("pem"), key: keyPem }
}
