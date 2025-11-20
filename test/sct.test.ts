import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";
import { X509Certificate } from "../src/x509/cert";
import { base64ToUint8Array } from "../src/encoding";

describe("Signed Certificate Timestamp (SCT) - Real Certificates", () => {
  const happyPathBundle = JSON.parse(
    readFileSync(
      join(__dirname, "./fixtures/sigstore/happy-path/bundle.sigstore.json"),
      "utf-8"
    )
  );

  const leafCertRaw = happyPathBundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes;
  const leafCertDER = base64ToUint8Array(leafCertRaw);
  const cert = X509Certificate.parse(leafCertDER);

  it("should parse SCT with valid log ID, timestamp, and signature", () => {
    const sct = cert.extSCT!.signedCertificateTimestamps[0];

    expect(cert.extSCT!.signedCertificateTimestamps.length).toBeGreaterThan(0);
    expect(sct.logID.length).toBe(32);
    expect(sct.datetime).toBeInstanceOf(Date);
    expect(!isNaN(sct.datetime.getTime())).toBe(true);
    expect(sct.datetime.getFullYear()).toBeGreaterThan(2020);
    expect(sct.datetime.getFullYear()).toBeLessThan(2030);
    expect(sct.signature.length).toBeGreaterThan(32);
    expect(sct.hashAlgorithm).toBeDefined();
    expect(sct.signatureAlgorithm).toBeDefined();
  });
});

describe("SCT Extension OID", () => {
  const happyPathBundle = JSON.parse(
    readFileSync(
      join(__dirname, "./fixtures/sigstore/happy-path/bundle.sigstore.json"),
      "utf-8"
    )
  );

  const leafCertRaw = happyPathBundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes;
  const leafCertDER = base64ToUint8Array(leafCertRaw);
  const cert = X509Certificate.parse(leafCertDER);

  it("should find SCT extension by OID with non-empty OCTET STRING value", () => {
    const sctExt = cert.extension("1.3.6.1.4.1.11129.2.4.2");

    expect(sctExt!.oid).toBe("1.3.6.1.4.1.11129.2.4.2");
    expect(sctExt!.value).toBeInstanceOf(Uint8Array);
    expect(sctExt!.value.length).toBeGreaterThan(32);
  });
});

describe("SCT Timestamp Validation", () => {
  const happyPathBundle = JSON.parse(
    readFileSync(
      join(__dirname, "./fixtures/sigstore/happy-path/bundle.sigstore.json"),
      "utf-8"
    )
  );

  const leafCertRaw = happyPathBundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes;
  const leafCertDER = base64ToUint8Array(leafCertRaw);
  const cert = X509Certificate.parse(leafCertDER);

  it("should have SCT timestamp within certificate validity period", () => {
    const sct = cert.extSCT!.signedCertificateTimestamps[0];

    expect(sct.datetime.getTime()).toBeLessThan(cert.notAfter.getTime());

    const timeDiff = Math.abs(sct.datetime.getTime() - cert.notBefore.getTime());
    expect(timeDiff).toBeLessThan(60 * 60 * 1000);
  });
});

describe("SCT - Multiple Certificates", () => {
  it("should parse SCT from expired certificate bundle", () => {
    const expiredBundle = JSON.parse(
      readFileSync(
        join(__dirname, "./fixtures/sigstore/intoto-expired-certificate_fail/bundle.sigstore.json"),
        "utf-8"
      )
    );

    const certRaw = expiredBundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes;
    const certDER = base64ToUint8Array(certRaw);
    const cert = X509Certificate.parse(certDER);

    expect(cert.extSCT).toBeDefined();
  });
});

describe("Certificate Transparency Log Integration", () => {
  const happyPathBundle = JSON.parse(
    readFileSync(
      join(__dirname, "./fixtures/sigstore/happy-path/bundle.sigstore.json"),
      "utf-8"
    )
  );

  const leafCertRaw = happyPathBundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes;
  const leafCertDER = base64ToUint8Array(leafCertRaw);
  const cert = X509Certificate.parse(leafCertDER);

  it("should have valid CT log ID and signature format", () => {
    const sct = cert.extSCT!.signedCertificateTimestamps[0];

    expect(cert.extSCT!.signedCertificateTimestamps.length).toBeGreaterThan(0);
    expect(sct.logID).toBeInstanceOf(Uint8Array);
    expect(sct.logID.length).toBe(32);
    expect(sct.signature).toBeInstanceOf(Uint8Array);
    expect(sct.signature.length).toBeGreaterThan(0);
  });
});

describe("Invalid CT Key Test Case", () => {
  const invalidCTBundle = JSON.parse(
    readFileSync(
      join(__dirname, "./fixtures/sigstore/invalid-ct-key_fail/bundle.sigstore.json"),
      "utf-8"
    )
  );

  const certRaw = invalidCTBundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes;
  const certDER = base64ToUint8Array(certRaw);

  it("should parse SCT structure even with invalid CT key", () => {
    const cert = X509Certificate.parse(certDER);

    expect(cert.extSCT).toBeDefined();
    expect(cert.extSCT!.signedCertificateTimestamps.length).toBeGreaterThan(0);
  });
});
