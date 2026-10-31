import { p256, p384 } from "@noble/curves/nist.js";
import { describe, expect, it } from "vitest";

import { sha256 } from "../src/crypto";
import { verifySignatureOverDigest } from "../src/noble";

// WebCrypto cannot verify ECDSA over a precomputed digest, so the noble path is the only one; pin it against
// signatures noble itself makes over the digest, imported through a real WebCrypto key.
describe("verifySignatureOverDigest", () => {
  const message = new TextEncoder().encode("artifact bytes the verifier never sees");

  async function keyFor(curve: typeof p256 | typeof p384, namedCurve: "P-256" | "P-384") {
    const priv = curve.utils.randomSecretKey();
    const pub = curve.getPublicKey(priv, false);
    const key = await crypto.subtle.importKey("raw", pub, { name: "ECDSA", namedCurve }, true, ["verify"]);
    return { priv, key };
  }

  it("verifies DER signatures over the digest on P-256 and P-384, and rejects tampering", async () => {
    const digest = await sha256(message);
    for (const [curve, namedCurve] of [
      [p256, "P-256"],
      [p384, "P-384"],
    ] as const) {
      const { priv, key } = await keyFor(curve, namedCurve);
      const sig = curve.sign(digest, priv, { prehash: false, format: "der" });
      expect(await verifySignatureOverDigest(key, digest, sig)).toBe(true);

      const other = await sha256(new Uint8Array([...message, 0]));
      expect(await verifySignatureOverDigest(key, other, sig)).toBe(false);
      const flipped = new Uint8Array(sig);
      flipped[flipped.length - 1] ^= 0x01;
      expect(await verifySignatureOverDigest(key, digest, flipped)).toBe(false);
    }
  });

  it("accepts a high-S signature, matching sigstore-js", async () => {
    const digest = await sha256(message);
    const { priv, key } = await keyFor(p256, "P-256");
    const sig = p256.sign(digest, priv, { prehash: false, format: "der", lowS: false });
    expect(await verifySignatureOverDigest(key, digest, sig)).toBe(true);
  });

  it("rejects non-ECDSA keys", async () => {
    const key = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    await expect(verifySignatureOverDigest(key.publicKey, new Uint8Array(32), new Uint8Array(70))).rejects.toThrow(
      "only supports ECDSA",
    );
  });
});
