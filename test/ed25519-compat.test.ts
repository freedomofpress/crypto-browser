import { afterEach, describe, expect, it, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";

import { subtleCryptoProxy, withEd25519Fallback } from "../src/crypto";
import { base64ToUint8Array, Uint8ArrayToBase64, uint8ArrayEqual } from "../src/encoding";
import { REKOR2_ED25519_SPKI_BASE64, rekor2Checkpoint } from "./fixtures/rekor2-ed25519";

// Native WebCrypto is the reference. The fallback must accept, reject and sign the same way.

const alg = { name: "Ed25519" };
const native = crypto.subtle;
const fallback = withEd25519Fallback(crypto.subtle);

const priv = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
// Wrap noble outputs so they type as BufferSource.
const pub = new Uint8Array(ed25519.getPublicKey(priv));
const nobleSign = (m: Uint8Array, k: Uint8Array) => new Uint8Array(ed25519.sign(m, k));
const spki = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, ...pub]);
const pkcs8 = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20, ...priv]);
const b64url = (b: Uint8Array) => Uint8ArrayToBase64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const jwkPub = { kty: "OKP", crv: "Ed25519", x: b64url(pub) };
const jwkPriv = { ...jwkPub, d: b64url(priv) };
const msg = new TextEncoder().encode("Ed25519 compatibility");
const otherMsg = new TextEncoder().encode("Ed25519 compatibility!");

const isFallback = (key: unknown) => (key as { __fallback__?: boolean }).__fallback__ === true;

// importKey has separate overloads for jwk and binary formats. This helper takes both.
type AnyImport = (format: KeyFormat, data: unknown, alg: Algorithm, extractable: boolean, usages: KeyUsage[]) => Promise<CryptoKey>;
const importAny = (subtle: SubtleCrypto, format: KeyFormat, data: unknown, usages: KeyUsage[]) =>
  (subtle.importKey as unknown as AnyImport)(format, data, alg, usages.includes("verify"), usages);

describe("Ed25519 fallback compatibility with native WebCrypto", () => {
  it("has native Ed25519 to compare against", async () => {
    await expect(native.generateKey(alg, false, ["sign", "verify"])).resolves.toBeDefined();
  });

  it("imports every public key format and cross-verifies with native", async () => {
    const nativePriv = await native.importKey("pkcs8", pkcs8, alg, false, ["sign"]);
    const nativeSig = new Uint8Array(await native.sign(alg, nativePriv, msg));
    const fallbackSig = nobleSign(msg, priv);

    for (const [format, data] of [["raw", pub], ["spki", spki], ["jwk", jwkPub]] as const) {
      const nativeKey = await importAny(native, format, data, ["verify"]);
      const fallbackKey = await importAny(fallback, format, data, ["verify"]);
      expect(isFallback(nativeKey)).toBe(false);
      expect(isFallback(fallbackKey)).toBe(true);
      expect(await native.verify(alg, nativeKey, fallbackSig, msg)).toBe(true);
      expect(await fallback.verify(alg, fallbackKey, nativeSig, msg)).toBe(true);
      expect(await fallback.verify(alg, fallbackKey, nativeSig, otherMsg)).toBe(false);
    }
  });

  it("imports every private key format and signs identically to native", async () => {
    // Native takes private keys as pkcs8 or jwk only. The fallback also takes raw.
    const nativePriv = await native.importKey("pkcs8", pkcs8, alg, false, ["sign"]);
    const reference = new Uint8Array(await native.sign(alg, nativePriv, msg));

    for (const [format, data] of [["raw", priv], ["pkcs8", pkcs8], ["jwk", jwkPriv]] as const) {
      const key = await importAny(fallback, format, data, ["sign"]);
      expect(isFallback(key)).toBe(true);
      expect(uint8ArrayEqual(new Uint8Array(await fallback.sign(alg, key, msg)), reference)).toBe(true);
    }
  });

  it("rejects every malformed key that native rejects", async () => {
    const x25519Spki = new Uint8Array(spki);
    x25519Spki[8] = 0x6e; // X25519 OID instead of Ed25519
    const malformed: Array<[KeyFormat, unknown, KeyUsage[]]> = [
      ["raw", pub.subarray(0, 31), ["verify"]],
      ["raw", spki, ["verify"]],
      ["spki", pub, ["verify"]],
      ["spki", x25519Spki, ["verify"]],
      ["spki", spki.subarray(0, 43), ["verify"]],
      ["pkcs8", priv, ["sign"]],
      ["pkcs8", pkcs8.subarray(0, 47), ["sign"]],
      ["jwk", { kty: "EC", crv: "Ed25519", x: jwkPub.x }, ["verify"]],
      ["jwk", { kty: "OKP", crv: "X25519", x: jwkPub.x }, ["verify"]],
      ["jwk", { kty: "OKP", crv: "Ed25519" }, ["verify"]],
    ];
    for (const [format, data, usages] of malformed) {
      await expect(importAny(native, format, data, usages), `native ${format}`).rejects.toThrow();
      await expect(importAny(fallback, format, data, usages), `fallback ${format}`).rejects.toMatchObject({ name: "DataError" });
    }
  });

  it("returns false for every malformed signature that native rejects", async () => {
    const nativeKey = await native.importKey("raw", pub, alg, true, ["verify"]);
    const fallbackKey = await fallback.importKey("raw", pub, alg, true, ["verify"]);
    const good = nobleSign(msg, priv);
    const highS = new Uint8Array(good);
    highS[63] |= 0xf0; // s above the group order
    for (const sig of [good.subarray(0, 63), new Uint8Array([...good, 0]), new Uint8Array(0), new Uint8Array(64), highS]) {
      expect(await native.verify(alg, nativeKey, sig, msg)).toBe(false);
      expect(await fallback.verify(alg, fallbackKey, sig, msg)).toBe(false);
    }
    // A public key that is not a curve point imports fine and fails to verify.
    const notAPoint = new Uint8Array(32).fill(0xff);
    expect(await native.verify(alg, await native.importKey("raw", notAPoint, alg, true, ["verify"]), good, msg)).toBe(false);
    expect(await fallback.verify(alg, await fallback.importKey("raw", notAPoint, alg, true, ["verify"]), good, msg)).toBe(false);
  });

  it("copies key bytes at import and accepts every BufferSource shape", async () => {
    const sig = nobleSign(msg, priv);
    const input = new Uint8Array(spki);
    const key = await fallback.importKey("spki", input, alg, true, ["verify"]);
    input.fill(0);
    expect(await fallback.verify(alg, key, sig, msg)).toBe(true);

    expect(await fallback.verify(alg, key, sig.buffer.slice(0), new DataView(msg.buffer.slice(0)))).toBe(true);
    // A view into a larger buffer must be read at its offset.
    const padded = new Uint8Array([0xaa, ...pub, 0xbb]);
    const viewKey = await fallback.importKey("raw", padded.subarray(1, 33), alg, true, ["verify"]);
    expect(await fallback.verify(alg, viewKey, sig, msg)).toBe(true);
  });

  it("still serves native Ed25519 keys through the proxy", async () => {
    const nativeKey = await native.importKey("raw", pub, alg, true, ["verify"]);
    const nativePriv = await native.importKey("pkcs8", pkcs8, alg, false, ["sign"]);
    const sig = await fallback.sign(alg, nativePriv, msg);
    expect(await fallback.verify(alg, nativeKey, sig, msg)).toBe(true);
  });

  it("uses native SubtleCrypto when Ed25519 is supported and the proxy when it is not", async () => {
    expect(await subtleCryptoProxy()).toBe(crypto.subtle);
    vi.spyOn(crypto.subtle, "generateKey").mockRejectedValueOnce(new DOMException("not supported", "NotSupportedError"));
    const proxied = await subtleCryptoProxy();
    vi.restoreAllMocks();
    expect(proxied).not.toBe(crypto.subtle);
    expect(isFallback(await proxied.importKey("raw", pub, alg, true, ["verify"]))).toBe(true);
  });

  it("passes other algorithms through to native", async () => {
    expect(uint8ArrayEqual(new Uint8Array(await fallback.digest("SHA-256", msg)), new Uint8Array(await native.digest("SHA-256", msg)))).toBe(true);

    const ecdsa = await fallback.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const ecdsaAlg = { name: "ECDSA", hash: "SHA-256" };
    const sig = await fallback.sign(ecdsaAlg, ecdsa.privateKey, msg);
    expect(await native.verify(ecdsaAlg, ecdsa.publicKey, sig, msg)).toBe(true);
    expect(await fallback.exportKey("jwk", ecdsa.publicKey)).toMatchObject({ kty: "EC", crv: "P-256" });

    const aes = await fallback.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const iv = new Uint8Array(12);
    const ciphertext = await fallback.encrypt({ name: "AES-GCM", iv }, aes, msg);
    expect(uint8ArrayEqual(new Uint8Array(await fallback.decrypt({ name: "AES-GCM", iv }, aes, ciphertext)), msg)).toBe(true);

    const hkdf = await fallback.importKey("raw", msg, "HKDF", false, ["deriveBits"]);
    const params = { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: new Uint8Array(0) };
    expect((await fallback.deriveBits(params, hkdf, 128)).byteLength).toBe(16);
  });
});

describe("Real Rekor checkpoint through importKey() and verifySignature()", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.resetModules();
  });

  // The library caches its SubtleCrypto choice per module. Load a fresh copy for each case.
  async function loadCrypto(forceFallback: boolean) {
    vi.resetModules();
    if (forceFallback) {
      vi.spyOn(crypto.subtle, "generateKey").mockRejectedValueOnce(new DOMException("not supported", "NotSupportedError"));
    }
    const mod = await import("../src/crypto");
    const subtle = await mod.getSubtle();
    vi.restoreAllMocks();
    return { mod, subtle };
  }

  const { signed, signature } = rekor2Checkpoint(base64ToUint8Array);

  for (const forceFallback of [false, true]) {
    const label = forceFallback ? "the fallback" : "native WebCrypto";
    it(`verifies the PKIX_ED25519 key and checkpoint with ${label}`, async () => {
      const { mod, subtle } = await loadCrypto(forceFallback);
      expect(subtle === crypto.subtle).toBe(!forceFallback);

      const key = await mod.importKey("PKIX_ED25519", "PKIX_ED25519", REKOR2_ED25519_SPKI_BASE64);
      expect(isFallback(key)).toBe(forceFallback);
      expect(await mod.verifySignature(key, signed, signature)).toBe(true);

      const tampered = new Uint8Array(signed);
      tampered[0] ^= 0x01;
      expect(await mod.verifySignature(key, tampered, signature)).toBe(false);
      // Wrong-length signatures must return false, not throw.
      expect(await mod.verifySignature(key, signed, signature.subarray(0, 63))).toBe(false);
      expect(await mod.verifySignature(key, signed, new Uint8Array(0))).toBe(false);
    });
  }

  it("imports the key from PEM and hex through the fallback", async () => {
    const { mod } = await loadCrypto(true);
    const pem = `-----BEGIN PUBLIC KEY-----\n${REKOR2_ED25519_SPKI_BASE64}\n-----END PUBLIC KEY-----\n`;
    const hex = Array.from(base64ToUint8Array(REKOR2_ED25519_SPKI_BASE64).subarray(12), (b) => b.toString(16).padStart(2, "0")).join("");
    for (const encoded of [pem, hex]) {
      const key = await mod.importKey("PKIX_ED25519", "PKIX_ED25519", encoded);
      expect(isFallback(key)).toBe(true);
      expect(await mod.verifySignature(key, signed, signature)).toBe(true);
    }
  });
});
