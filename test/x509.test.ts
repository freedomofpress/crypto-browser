import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";
import { X509Certificate } from "../src/x509/cert";
import { verifyCertificateChain } from "../src/x509/chain";
import { base64ToUint8Array } from "../src/encoding";

describe("X.509 Certificate Parsing - Real Fulcio Certificates", () => {
  const happyPathBundle = JSON.parse(
    readFileSync(
      join(__dirname, "./fixtures/sigstore/happy-path/bundle.sigstore.json"),
      "utf-8"
    )
  );

  const leafCertRaw = happyPathBundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes;
  const leafCertDER = base64ToUint8Array(leafCertRaw);

  it("should parse Fulcio certificate with all required fields", () => {
    const cert = X509Certificate.parse(leafCertDER);

    expect(cert.subject).toBeInstanceOf(Uint8Array);
    expect(cert.issuer).toBeInstanceOf(Uint8Array);
    expect(cert.issuer.length).toBeGreaterThan(0);
    expect(cert.serialNumber.length).toBeGreaterThan(0);
    expect(cert.publicKey.length).toBeGreaterThan(32);
    expect(cert.signatureValue.length).toBeGreaterThan(32);
    expect(cert.signatureAlgorithm).toBeDefined();
    expect(cert.tbsCertificate.toDER().length).toBeGreaterThan(100);
    expect(cert.notBefore.getTime()).toBeLessThan(cert.notAfter.getTime());
  });
});

describe("X.509 Extensions - Fulcio Specific", () => {
  const happyPathBundle = JSON.parse(
    readFileSync(
      join(__dirname, "./fixtures/sigstore/happy-path/bundle.sigstore.json"),
      "utf-8"
    )
  );

  const leafCertRaw = happyPathBundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes;
  const leafCertDER = base64ToUint8Array(leafCertRaw);

  it("should parse all Fulcio-specific extensions", () => {
    const cert = X509Certificate.parse(leafCertDER);

    expect(cert.extensions.length).toBeGreaterThan(5);
    expect(cert.extSubjectAltName?.uri.length).toBeGreaterThan(0);
    expect(cert.extKeyUsage).toBeDefined();
    expect(cert.extSubjectKeyID).toBeDefined();
    expect(cert.extAuthorityKeyID).toBeDefined();
    expect(cert.extSCT).toBeDefined();
    expect(cert.extension("1.3.6.1.4.1.57264.1.1")).toBeDefined();
  });
});

describe("X.509 Certificate Validation", () => {
  const happyPathBundle = JSON.parse(
    readFileSync(
      join(__dirname, "./fixtures/sigstore/happy-path/bundle.sigstore.json"),
      "utf-8"
    )
  );

  const leafCertRaw = happyPathBundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes;
  const leafCertDER = base64ToUint8Array(leafCertRaw);

  it("should correctly validate certificate temporal validity", () => {
    const cert = X509Certificate.parse(leafCertDER);

    expect(cert.validForDate(new Date("2023-07-12T16:00:00Z"))).toBe(true);
    expect(cert.validForDate(new Date("2099-01-01T00:00:00Z"))).toBe(false);
    expect(cert.validForDate(new Date("2020-01-01T00:00:00Z"))).toBe(false);
    expect(cert.isCA).toBe(false);
  });
});

describe("X.509 Certificate Parsing - Expired Certificate", () => {
  const expiredBundle = JSON.parse(
    readFileSync(
      join(__dirname, "./fixtures/sigstore/intoto-expired-certificate_fail/bundle.sigstore.json"),
      "utf-8"
    )
  );

  const expiredCertRaw = expiredBundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes;
  const expiredCertDER = base64ToUint8Array(expiredCertRaw);

  it("should detect certificate as expired at integrated time", () => {
    const cert = X509Certificate.parse(expiredCertDER);
    const bundle = expiredBundle;

    const integratedTime = new Date(
      parseInt(bundle.verificationMaterial.tlogEntries[0].integratedTime) * 1000
    );

    expect(cert.validForDate(integratedTime)).toBe(false);
  });
});

describe("ASN.1 Parsing - Real Certificate Structures", () => {
  const happyPathBundle = JSON.parse(
    readFileSync(
      join(__dirname, "./fixtures/sigstore/happy-path/bundle.sigstore.json"),
      "utf-8"
    )
  );

  const leafCertRaw = happyPathBundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes;
  const leafCertDER = base64ToUint8Array(leafCertRaw);

  it("should parse complex certificate with OIDs, dates, and binary data", () => {
    const cert = X509Certificate.parse(leafCertDER);

    expect(cert.extensions.length).toBeGreaterThan(10);

    const extensionOIDs = cert.extensions.map((ext) => ext.subs[0].toOID());
    expect(extensionOIDs).toContain("2.5.29.17");
    expect(extensionOIDs).toContain("2.5.29.15");

    expect(!isNaN(cert.notBefore.getTime())).toBe(true);
    expect(!isNaN(cert.notAfter.getTime())).toBe(true);

    expect(cert.publicKey.length).toBeGreaterThan(32);
    expect(cert.extension("2.5.29.17")?.value).toBeInstanceOf(Uint8Array);
  });
});

describe("Certificate Chain Verification - Real Sigstore Bundles", () => {
  it("should verify certificate was valid at transparency log integrated time", () => {
    const happyPathBundle = JSON.parse(
      readFileSync(
        join(__dirname, "./fixtures/sigstore/happy-path/bundle.sigstore.json"),
        "utf-8"
      )
    );

    const leafCertRaw = happyPathBundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes;
    const leafCertDER = base64ToUint8Array(leafCertRaw);
    const cert = X509Certificate.parse(leafCertDER);

    const integratedTimeSeconds = parseInt(happyPathBundle.verificationMaterial.tlogEntries[0].integratedTime);
    const integratedTime = new Date(integratedTimeSeconds * 1000);

    expect(integratedTimeSeconds).toBe(1689177396);
    expect(cert.validForDate(integratedTime)).toBe(true);
  });
});

describe("Signature Verification - Real Sigstore Signatures", () => {
  const happyPathBundle = JSON.parse(
    readFileSync(
      join(__dirname, "./fixtures/sigstore/happy-path/bundle.sigstore.json"),
      "utf-8"
    )
  );

  it("should extract and decode signature and digest from bundle", () => {
    const signatureB64 = happyPathBundle.messageSignature.signature;
    const digestB64 = happyPathBundle.messageSignature.messageDigest.digest;
    const algorithm = happyPathBundle.messageSignature.messageDigest.algorithm;

    expect(algorithm).toBe("SHA2_256");

    const signatureBytes = base64ToUint8Array(signatureB64);
    const digestBytes = base64ToUint8Array(digestB64);

    expect(signatureBytes).toBeInstanceOf(Uint8Array);
    expect(signatureBytes.length).toBeGreaterThan(32);
    expect(digestBytes).toBeInstanceOf(Uint8Array);
    expect(digestBytes.length).toBe(32);
  });
});

describe("Transparency Log Entry Parsing", () => {
  const happyPathBundle = JSON.parse(
    readFileSync(
      join(__dirname, "./fixtures/sigstore/happy-path/bundle.sigstore.json"),
      "utf-8"
    )
  );

  const tlogEntry = happyPathBundle.verificationMaterial.tlogEntries[0];

  it("should decode and parse transparency log canonicalized body as JSON", () => {
    const body = base64ToUint8Array(tlogEntry.canonicalizedBody);
    const bodyJSON = JSON.parse(new TextDecoder().decode(body));

    expect(body.length).toBeGreaterThan(100);
    expect(bodyJSON.apiVersion).toBe("0.0.1");
    expect(bodyJSON.kind).toBe("hashedrekord");
    expect(bodyJSON.spec.signature.publicKey.content).toBeDefined();
  });
});

