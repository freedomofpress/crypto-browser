import { readFileSync } from "fs";
import { join } from "path";
import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";

import { ASN1Obj } from "../src/asn1/obj";
import { ASN1Tag } from "../src/asn1/tag";
import { importKey, verifySignature, withEd25519Fallback } from "../src/crypto";
import { base64ToUint8Array, Uint8ArrayToBase64, uint8ArrayEqual } from "../src/encoding";

const bundle = JSON.parse(
  readFileSync(join(__dirname, "./fixtures/sigstore/happy-path/bundle.sigstore.json"), "utf-8")
);
const leafDER: Uint8Array = base64ToUint8Array(
  bundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes
);

// Wraps `inner` in `depth` SEQUENCEs (or OCTET STRINGs) using minimal DER lengths.
function nested(depth: number, tag = 0x30): Uint8Array {
  let buf = new Uint8Array([0x05, 0x00]);
  for (let i = 0; i < depth; i++) {
    const len = buf.length;
    const hdr = len < 128 ? [tag, len] : len < 256 ? [tag, 0x81, len] : [tag, 0x82, len >> 8, len & 0xff];
    const next = new Uint8Array(hdr.length + len);
    next.set(hdr);
    next.set(buf, hdr.length);
    buf = next;
  }
  return buf;
}

describe("Strict DER parsing", () => {
  it("still parses a real certificate", () => {
    expect(ASN1Obj.parseBuffer(leafDER).subs).toHaveLength(3);
  });

  it("rejects trailing bytes", () => {
    expect(() => ASN1Obj.parseBuffer(new Uint8Array([...leafDER, 0x00]))).toThrow("trailing bytes");
  });

  it("rejects non-minimal length encodings", () => {
    expect(() => ASN1Obj.parseBuffer(new Uint8Array([0x30, 0x81, 0x02, 0x05, 0x00]))).toThrow("non-minimal length");
    expect(() => ASN1Obj.parseBuffer(new Uint8Array([0x30, 0x83, 0x00, ...leafDER.subarray(2)]))).toThrow("non-minimal length");
  });

  it("rejects non-minimal integers and non-DER booleans", () => {
    expect(ASN1Obj.parseBuffer(new Uint8Array([0x02, 0x02, 0x00, 0x80])).toInteger()).toBe(128n);
    expect(() => ASN1Obj.parseBuffer(new Uint8Array([0x02, 0x02, 0x00, 0x01])).toInteger()).toThrow("non-minimal integer");
    expect(() => ASN1Obj.parseBuffer(new Uint8Array([0x02, 0x00])).toInteger()).toThrow("non-minimal integer");
    expect(ASN1Obj.parseBuffer(new Uint8Array([0x01, 0x01, 0xff])).toBoolean()).toBe(true);
    expect(() => ASN1Obj.parseBuffer(new Uint8Array([0x01, 0x01, 0x01])).toBoolean()).toThrow("invalid boolean");
  });

  it("bounds nesting depth instead of exhausting the stack", () => {
    expect(ASN1Obj.parseBuffer(nested(30)).subs).toHaveLength(1);
    expect(() => ASN1Obj.parseBuffer(nested(33))).toThrow("nesting too deep");
    expect(() => ASN1Obj.parseBuffer(nested(8000))).toThrow("nesting too deep");
    // OCTET STRING contents are parsed speculatively; too deep falls back to primitive rather than crashing.
    expect(ASN1Obj.parseBuffer(nested(8000, 0x04))).toBeInstanceOf(ASN1Obj);
  });
});

describe("Ed25519 fallback", () => {
  const subtle = withEd25519Fallback(crypto.subtle);
  const priv = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
  const pub = ed25519.getPublicKey(priv);
  const spki = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, ...pub]);
  const pkcs8 = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20, ...priv]);
  const msg = new TextEncoder().encode("checkpoint");
  const alg = { name: "Ed25519" };

  it("imports public keys from raw, spki and jwk and verifies noble signatures", async () => {
    const sig = ed25519.sign(msg, priv);
    const b64url = Uint8ArrayToBase64(pub).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    for (const [format, data] of [["raw", pub], ["spki", spki], ["jwk", { kty: "OKP", crv: "Ed25519", x: b64url }]] as const) {
      const key = await subtle.importKey(format, data as never, alg, true, ["verify"]);
      expect((key as unknown as { bytes: Uint8Array }).bytes).toHaveLength(32);
      expect(await subtle.verify(alg, key, sig, msg)).toBe(true);
      expect(await subtle.verify(alg, key, sig, new Uint8Array([1]))).toBe(false);
    }
  });

  it("imports private keys from raw and pkcs8 and signs like noble", async () => {
    for (const [format, data] of [["raw", priv], ["pkcs8", pkcs8]] as const) {
      const key = await subtle.importKey(format, data, alg, false, ["sign"]);
      const sig = new Uint8Array(await subtle.sign(alg, key, msg));
      expect(uint8ArrayEqual(sig, ed25519.sign(msg, priv))).toBe(true);
    }
  });

  it("rejects malformed keys and passes other algorithms through with a bound receiver", async () => {
    await expect(subtle.importKey("spki", pub, alg, true, ["verify"])).rejects.toThrow("Invalid Ed25519 spki key");
    await expect(subtle.importKey("raw", spki, alg, true, ["verify"])).rejects.toThrow("Invalid Ed25519 raw key");
    expect(new Uint8Array(await subtle.digest("SHA-256", msg))).toHaveLength(32);
    const ecdsa = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    expect((await subtle.exportKey("jwk", ecdsa.publicKey)).kty).toBe("EC");
  });

  it("imports the base64 SPKI format used by Sigstore trusted roots through importKey()", async () => {
    // importKey() routes through the cached subtle, so this checks the SPKI path end to end when native support is present.
    const key = await importKey("PKIX_ED25519", "PKIX_ED25519", Uint8ArrayToBase64(spki));
    expect(await verifySignature(key, msg, ed25519.sign(msg, priv))).toBe(true);
  });
});

describe("Strict ECDSA signature encoding", () => {
  // Minimal DER INTEGER for a positive bigint.
  const integer = (n: bigint) => {
    let hex = n.toString(16);
    if (hex.length % 2) hex = "0" + hex;
    const bytes = hex.match(/../g)!.map((h) => parseInt(h, 16));
    if (bytes[0] & 0x80) bytes.unshift(0);
    return new ASN1Obj(new ASN1Tag(0x02), new Uint8Array(bytes), []);
  };
  const der = (...ints: ASN1Obj[]) => new ASN1Obj(new ASN1Tag(0x30), new Uint8Array(0), ints).toDER();

  it("accepts canonical signatures and rejects trailing bytes, padded integers and extra fields", async () => {
    const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const msg = new TextEncoder().encode("artifact");
    const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, msg));
    const toBig = (b: Uint8Array) => BigInt("0x" + Array.from(b, (x) => x.toString(16).padStart(2, "0")).join(""));
    const r = toBig(raw.subarray(0, 32));
    const s = toBig(raw.subarray(32));

    expect(await verifySignature(kp.publicKey, msg, der(integer(r), integer(s)))).toBe(true);
    expect(await verifySignature(kp.publicKey, msg, new Uint8Array([...der(integer(r), integer(s)), 0x00]))).toBe(false);
    const padded = new ASN1Obj(new ASN1Tag(0x02), new Uint8Array([0x00, ...integer(r).value]), []);
    expect(await verifySignature(kp.publicKey, msg, der(padded, integer(s)))).toBe(false);
    expect(await verifySignature(kp.publicKey, msg, der(integer(r), integer(s), integer(1n)))).toBe(false);
    expect(await verifySignature(kp.publicKey, msg, der(integer(r)))).toBe(false);
  });
});
