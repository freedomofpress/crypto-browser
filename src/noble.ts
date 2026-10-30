import { ed25519 } from "@noble/curves/ed25519.js";
import { p256, p384, p521 } from "@noble/curves/nist.js";

import { getSubtle, setSubtle } from "./crypto.js";
import { base64UrlToUint8Array } from "./encoding.js";
import { EcdsaTypes, KeyTypes } from "./interfaces.js";

// Ed25519 is not part of the Web Crypto API W3C spec, and is optionally implemented
// by browsers. This proxy allows us to provide a fallback implementation using
// @noble/curves when native support is not available, while still using the native
// SubtleCrypto for all other operations and algorithms. The proxy intercepts calls
// to importKey(), sign(), and verify() to handle Ed25519 keys and operations,
// while passing through everything else to the native SubtleCrypto.
type FallbackCryptoKey = {
  __fallback__: true;
  algorithm: { name: "Ed25519" };
  type: "public" | "private";
  bytes: Uint8Array;
};

const algorithmName = (algorithm: AlgorithmIdentifier): string =>
  typeof algorithm === "string" ? algorithm : algorithm.name;

function isFallbackKey(key: unknown): key is FallbackCryptoKey {
  return typeof key === "object" && key !== null && (key as { __fallback__?: unknown }).__fallback__ === true;
}

function toUint8(data: BufferSource): Uint8Array {
  return data instanceof ArrayBuffer
    ? new Uint8Array(data)
    : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
}

async function isEd25519Available(): Promise<boolean> {
  try {
    await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
    return true;
  } catch {
    return false;
  }
}

export async function subtleCryptoProxy(): Promise<SubtleCrypto> {
  return (await isEd25519Available()) ? crypto.subtle : withEd25519Fallback(crypto.subtle);
}

// Fixed DER prefixes of an Ed25519 SubjectPublicKeyInfo and PKCS#8 PrivateKeyInfo; the 32 key bytes follow.
const ED25519_SPKI_PREFIX = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
const ED25519_PKCS8_PREFIX = [
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

// Extracts the raw 32-byte Ed25519 key from any WebCrypto import format.
function ed25519KeyBytes(format: KeyFormat, keyData: BufferSource | JsonWebKey, isPrivate: boolean): Uint8Array {
  let bytes: Uint8Array;
  let prefix: number[] = [];
  if (format === "jwk") {
    const jwk = keyData as JsonWebKey;
    const field = isPrivate ? jwk.d : jwk.x;
    if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !field) {
      throw new DOMException("Invalid Ed25519 JWK", "DataError");
    }
    bytes = base64UrlToUint8Array(field);
  } else {
    bytes = toUint8(keyData as BufferSource);
    prefix = format === "spki" ? ED25519_SPKI_PREFIX : format === "pkcs8" ? ED25519_PKCS8_PREFIX : [];
  }
  if (bytes.length !== prefix.length + 32 || !prefix.every((b, i) => bytes[i] === b)) {
    throw new DOMException(`Invalid Ed25519 ${format} key`, "DataError");
  }
  // Copy so later writes to the caller's buffer cannot change the key.
  return bytes.slice(prefix.length);
}

// Wraps a SubtleCrypto so Ed25519 importKey(), sign() and verify() run on @noble/curves; everything else passes through.
export function withEd25519Fallback(subtle: SubtleCrypto): SubtleCrypto {
  return new Proxy(subtle, {
    get(target, prop: keyof SubtleCrypto) {
      if (prop === "importKey") {
        return async function (
          format: KeyFormat,
          keyData: BufferSource | JsonWebKey,
          algorithm: AlgorithmIdentifier,
          extractable: boolean,
          usages: KeyUsage[],
        ) {
          if (algorithmName(algorithm) === "Ed25519") {
            const type: "public" | "private" = usages.includes("sign") ? "private" : "public";
            return {
              __fallback__: true,
              algorithm: { name: "Ed25519" },
              type,
              bytes: ed25519KeyBytes(format, keyData, type === "private"),
            } as FallbackCryptoKey;
          }
          return format === "jwk"
            ? target.importKey("jwk", keyData as JsonWebKey, algorithm, extractable, usages)
            : target.importKey(format, keyData as BufferSource, algorithm, extractable, usages);
        };
      }

      if (prop === "sign") {
        return async function (algorithm: AlgorithmIdentifier, key: CryptoKey | FallbackCryptoKey, data: BufferSource) {
          if (algorithmName(algorithm) === "Ed25519" && isFallbackKey(key)) {
            if (key.type !== "private") {
              throw new DOMException("Invalid key type for signing", "InvalidAccessError");
            }
            return ed25519.sign(toUint8(data), key.bytes).buffer;
          }
          return target.sign(algorithm, key as CryptoKey, data);
        };
      }

      if (prop === "verify") {
        return async function (
          algorithm: AlgorithmIdentifier,
          key: CryptoKey | FallbackCryptoKey,
          signature: BufferSource,
          data: BufferSource,
        ) {
          if (algorithmName(algorithm) === "Ed25519" && isFallbackKey(key)) {
            if (key.type !== "public") {
              throw new DOMException("Invalid key type for verify", "InvalidAccessError");
            }
            // noble throws on a malformed signature. Native returns false, so do the same.
            try {
              return ed25519.verify(toUint8(signature), toUint8(data), key.bytes);
            } catch {
              return false;
            }
          }
          return target.verify(algorithm, key as CryptoKey, signature, data);
        };
      }

      // Native methods brand-check `this`, so they must stay bound to the real SubtleCrypto.
      const value = Reflect.get(target, prop);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

// Routes every crypto-browser helper through the fallback when the platform lacks native Ed25519.
export function installEd25519Fallback(): Promise<SubtleCrypto> {
  const subtle = subtleCryptoProxy();
  setSubtle(subtle);
  return subtle;
}

// Verifies an ECDSA signature over a pre-computed digest.
// WebCrypto's verify() always hashes the input first, so passing a digest would
// result in double-hashing. We use @noble/curves for low-level ECDSA verification,
// adapted from the same workaround used in sigstore-js's conformance CLI.
// See: https://github.com/sigstore/sigstore-js/blob/main/packages/conformance/src/commands/verify-bundle.ts#L111
export async function verifySignatureOverDigest(key: CryptoKey, digest: Uint8Array, sig: Uint8Array): Promise<boolean> {
  const subtle = await getSubtle();
  if (key.algorithm.name !== KeyTypes.Ecdsa) {
    throw new Error("verifySignatureOverDigest only supports ECDSA keys");
  }

  const namedCurve = (key.algorithm as EcKeyAlgorithm).namedCurve;
  let curve: typeof p256 | typeof p384 | typeof p521;

  if (namedCurve === EcdsaTypes.P256) {
    curve = p256;
  } else if (namedCurve === EcdsaTypes.P384) {
    curve = p384;
  } else if (namedCurve === EcdsaTypes.P521) {
    curve = p521;
  } else {
    throw new Error(`Unsupported curve: ${namedCurve}`);
  }

  // Export the public key to get x and y coordinates
  const jwk = await subtle.exportKey("jwk", key);
  if (!jwk.x || !jwk.y) {
    throw new Error("Invalid ECDSA public key: missing x or y coordinates");
  }

  // Convert base64url JWK coordinates to bytes
  const x = base64UrlToUint8Array(jwk.x);
  const y = base64UrlToUint8Array(jwk.y);

  // Combine x and y into uncompressed public key format (0x04 || x || y)
  const publicKey = new Uint8Array(1 + x.length + y.length);
  publicKey[0] = 0x04;
  publicKey.set(x, 1);
  publicKey.set(y, 1 + x.length);

  // Verify the DER-encoded signature over the digest
  // @noble/curves can parse DER signatures directly with format: 'der'
  // Options:
  // - format: 'der' to parse DER-encoded signatures
  // - prehash: false because we're passing a pre-computed digest, not the original message
  // - lowS: false to accept both high-S and low-S signatures (matches elliptic.js behavior)
  //   elliptic.js accepts malleable signatures by default, while @noble/curves rejects them by default
  return curve.verify(sig, digest, publicKey, { format: "der", prehash: false, lowS: false });
}
