import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";
import { ASN1Obj } from "../src/asn1/obj";
import { base64ToUint8Array } from "../src/encoding";
import { X509Certificate } from "../src/x509/cert";

describe("ASN.1 Parsing - Real Certificate Data", () => {
  const happyPathBundle = JSON.parse(
    readFileSync(
      join(__dirname, "./fixtures/sigstore/happy-path/bundle.sigstore.json"),
      "utf-8"
    )
  );

  const leafCertRaw = happyPathBundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes;
  const leafCertDER = base64ToUint8Array(leafCertRaw);

  it("should parse certificate as SEQUENCE with 3 children (TBS, sigAlg, signature)", () => {
    const asn1 = ASN1Obj.parseBuffer(leafCertDER);

    expect(asn1.tag.number).toBe(0x10);
    expect(asn1.tag.constructed).toBe(true);
    expect(asn1.subs.length).toBe(3);
    expect(asn1.subs[0].tag.constructed).toBe(true);
    expect(asn1.subs[1].tag.constructed).toBe(true);
    expect(asn1.subs[2].tag.number).toBe(0x03);
  });
});

describe("ASN.1 OID Parsing - Certificate Extensions", () => {
  const happyPathBundle = JSON.parse(
    readFileSync(
      join(__dirname, "./fixtures/sigstore/happy-path/bundle.sigstore.json"),
      "utf-8"
    )
  );

  const leafCertRaw = happyPathBundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes;
  const leafCertDER = base64ToUint8Array(leafCertRaw);
  const cert = X509Certificate.parse(leafCertDER);

  it("should parse standard X.509 extension OIDs", () => {
    expect(cert.extension("2.5.29.17")?.oid).toBe("2.5.29.17");
    expect(cert.extension("2.5.29.15")?.oid).toBe("2.5.29.15");
    expect(cert.extension("2.5.29.14")?.oid).toBe("2.5.29.14");
    expect(cert.extension("2.5.29.35")?.oid).toBe("2.5.29.35");
  });

  it("should parse Fulcio and CT extension OIDs", () => {
    expect(cert.extension("1.3.6.1.4.1.57264.1.1")).toBeDefined();
    expect(cert.extension("1.3.6.1.4.1.11129.2.4.2")).toBeDefined();
  });
});

describe("ASN.1 Date Parsing - Certificate Validity", () => {
  const happyPathBundle = JSON.parse(
    readFileSync(
      join(__dirname, "./fixtures/sigstore/happy-path/bundle.sigstore.json"),
      "utf-8"
    )
  );

  const leafCertRaw = happyPathBundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes;
  const leafCertDER = base64ToUint8Array(leafCertRaw);
  const cert = X509Certificate.parse(leafCertDER);

  it("should parse validity dates in correct temporal order", () => {
    expect(cert.notBefore).toBeInstanceOf(Date);
    expect(cert.notAfter).toBeInstanceOf(Date);
    expect(!isNaN(cert.notBefore.getTime())).toBe(true);
    expect(!isNaN(cert.notAfter.getTime())).toBe(true);
    expect(cert.notBefore.getTime()).toBeLessThan(cert.notAfter.getTime());
    expect(cert.notBefore.getFullYear()).toBeGreaterThan(2020);
  });
});

describe("ASN.1 Integer Parsing - Serial Number", () => {
  const happyPathBundle = JSON.parse(
    readFileSync(
      join(__dirname, "./fixtures/sigstore/happy-path/bundle.sigstore.json"),
      "utf-8"
    )
  );

  const leafCertRaw = happyPathBundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes;
  const leafCertDER = base64ToUint8Array(leafCertRaw);
  const cert = X509Certificate.parse(leafCertDER);

  it("should parse serial number as bytes", () => {
    expect(cert.serialNumber).toBeInstanceOf(Uint8Array);
    expect(cert.serialNumber.length).toBeGreaterThan(0);
  });

});

describe("ASN.1 BIT STRING - Public Key and Signature", () => {
  const happyPathBundle = JSON.parse(
    readFileSync(
      join(__dirname, "./fixtures/sigstore/happy-path/bundle.sigstore.json"),
      "utf-8"
    )
  );

  const leafCertRaw = happyPathBundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes;
  const leafCertDER = base64ToUint8Array(leafCertRaw);
  const cert = X509Certificate.parse(leafCertDER);

  it("should parse public key and signature as non-empty BIT STRINGs", () => {
    expect(cert.publicKey).toBeInstanceOf(Uint8Array);
    expect(cert.publicKey.length).toBeGreaterThan(32);
    expect(cert.signatureValue).toBeInstanceOf(Uint8Array);
    expect(cert.signatureValue.length).toBeGreaterThan(32);
  });

});

describe("ASN.1 OCTET STRING - Extension Values", () => {
  const happyPathBundle = JSON.parse(
    readFileSync(
      join(__dirname, "./fixtures/sigstore/happy-path/bundle.sigstore.json"),
      "utf-8"
    )
  );

  const leafCertRaw = happyPathBundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes;
  const leafCertDER = base64ToUint8Array(leafCertRaw);
  const cert = X509Certificate.parse(leafCertDER);

  it("should parse extension values as OCTET STRINGs containing nested ASN.1", () => {
    const sanExt = cert.extension("2.5.29.17");
    expect(sanExt!.value).toBeInstanceOf(Uint8Array);
    expect(sanExt!.value.length).toBeGreaterThan(0);

    const innerAsn1 = ASN1Obj.parseBuffer(sanExt!.value);
    expect(innerAsn1.tag).toBeDefined();

    const skiExt = cert.extension("2.5.29.14");
    expect(skiExt!.value).toBeInstanceOf(Uint8Array);
    expect(skiExt!.value.length).toBeGreaterThan(0);
  });
});

describe("ASN.1 Length Encoding - Various Lengths", () => {
  const happyPathBundle = JSON.parse(
    readFileSync(
      join(__dirname, "./fixtures/sigstore/happy-path/bundle.sigstore.json"),
      "utf-8"
    )
  );

  const leafCertRaw = happyPathBundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes;
  const leafCertDER = base64ToUint8Array(leafCertRaw);

  it("should handle certificate with length > 255 bytes", () => {
    expect(leafCertDER.length).toBeGreaterThan(255);

    const asn1 = ASN1Obj.parseBuffer(leafCertDER);
    expect(asn1).toBeDefined();
  });
});

describe("ASN.1 Parsing - Multiple Test Bundles", () => {
  it("should parse certificates from various test bundles", () => {
    const bundles = [
      "intoto-expired-certificate_fail/bundle.sigstore.json",
      "signature-mismatch_fail/bundle.sigstore.json"
    ];

    bundles.forEach(bundlePath => {
      const bundle = JSON.parse(
        readFileSync(join(__dirname, `../test/fixtures/sigstore/${bundlePath}`), "utf-8")
      );
      const certRaw = bundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes;
      const certDER = base64ToUint8Array(certRaw);
      const asn1 = ASN1Obj.parseBuffer(certDER);

      expect(asn1.tag.number).toBe(0x10);
      expect(asn1.subs.length).toBe(3);
    });
  });
});

describe("ASN.1 Tag Types - Universal Tags", () => {
  const happyPathBundle = JSON.parse(
    readFileSync(
      join(__dirname, "./fixtures/sigstore/happy-path/bundle.sigstore.json"),
      "utf-8"
    )
  );

  const leafCertRaw = happyPathBundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes;
  const leafCertDER = base64ToUint8Array(leafCertRaw);

  it("should correctly identify tag properties (constructed, universal, SEQUENCE)", () => {
    const asn1 = ASN1Obj.parseBuffer(leafCertDER);

    expect(asn1.tag.number).toBe(0x10);
    expect(asn1.tag.constructed).toBe(true);
    expect(asn1.tag.isUniversal()).toBe(true);
  });
});
