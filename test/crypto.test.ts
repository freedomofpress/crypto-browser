import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";
import { X509Certificate } from "../src/x509/cert";
import { base64ToUint8Array } from "../src/encoding";
import { importKey } from "../src/crypto";

async function hash(algorithm: string, data: BufferSource): Promise<Uint8Array> {
  const hashBuffer = await crypto.subtle.digest(algorithm, data);
  return new Uint8Array(hashBuffer);
}

describe("Signature Verification - Real Sigstore Bundles", () => {
  const happyPathBundle = JSON.parse(
    readFileSync(
      join(__dirname, "./fixtures/sigstore/happy-path/bundle.sigstore.json"),
      "utf-8"
    )
  );

  const leafCertRaw = happyPathBundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes;
  const leafCertDER = base64ToUint8Array(leafCertRaw);
  const cert = X509Certificate.parse(leafCertDER);

  it("should extract signature components for ECDSA P-256 verification", () => {
    expect(cert.publicKey.length).toBeGreaterThan(32);

    const signatureB64 = happyPathBundle.messageSignature.signature;
    const signature = base64ToUint8Array(signatureB64);
    expect(signature.length).toBeGreaterThan(32);

    const digestB64 = happyPathBundle.messageSignature.messageDigest.digest;
    const digest = base64ToUint8Array(digestB64);
    expect(digest.length).toBe(32);
  });

  it("should compute SHA-256 hash matching expected length", async () => {
    const testData = new TextEncoder().encode("a\n");
    const digest = await hash("SHA-256", testData);

    expect(digest.length).toBe(32);
  });

});



describe("Hash Algorithms - Real Bundle Data", () => {
  const happyPathBundle = JSON.parse(
    readFileSync(
      join(__dirname, "./fixtures/sigstore/happy-path/bundle.sigstore.json"),
      "utf-8"
    )
  );

  it("should produce deterministic SHA-256 hashes with correct length", async () => {
    const algorithm = happyPathBundle.messageSignature.messageDigest.algorithm;
    expect(algorithm).toBe("SHA2_256");

    const data = new TextEncoder().encode("test data");
    const digest1 = await hash("SHA-256", data);
    const digest2 = await hash("SHA-256", data);

    expect(digest1.length).toBe(32);
    expect(digest1).toEqual(digest2);

    const differentData = new TextEncoder().encode("different");
    const digest3 = await hash("SHA-256", differentData);
    expect(digest3).not.toEqual(digest1);
  });
});

describe("Canonicalized Body - Transparency Log", () => {
  const happyPathBundle = JSON.parse(
    readFileSync(
      join(__dirname, "./fixtures/sigstore/happy-path/bundle.sigstore.json"),
      "utf-8"
    )
  );

  const tlogEntry = happyPathBundle.verificationMaterial.tlogEntries[0];

  it("should extract signature and hash data from canonicalized body", () => {
    const body = base64ToUint8Array(tlogEntry.canonicalizedBody);
    const bodyJSON = JSON.parse(new TextDecoder().decode(body));

    expect(bodyJSON.spec.signature.publicKey.content).toBeDefined();
    expect(typeof bodyJSON.spec.signature.content).toBe("string");
    expect(bodyJSON.spec.data.hash.algorithm).toBe("sha256");
    expect(bodyJSON.spec.data.hash.value).toBeDefined();
  });
});
