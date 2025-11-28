import { describe, it, expect } from "vitest";
import {
  base64ToUint8Array,
  Uint8ArrayToBase64,
  hexToUint8Array,
  Uint8ArrayToHex,
  stringToUint8Array,
  Uint8ArrayToString,
  uint8ArrayEqual,
  base64UrlToUint8Array,
} from "../src/encoding.js";
import { toDER, fromDER } from "../src/pem.js";
import { canonicalize } from "../src/canonicalize.js";
import { ByteStream } from "../src/stream.js";
import { ASN1Obj } from "../src/asn1/obj.js";
import { importKey, verifySignature } from "../src/crypto.js";

describe("Crypto Browser Compatibility Tests", () => {
  describe("Browser Environment", () => {
    it("should have crypto.subtle available", () => {
      expect(globalThis.crypto).toBeDefined();
      expect(globalThis.crypto.subtle).toBeDefined();
    });

    it("should have TextEncoder/TextDecoder available", () => {
      expect(TextEncoder).toBeDefined();
      expect(TextDecoder).toBeDefined();
      const encoder = new TextEncoder();
      const decoder = new TextDecoder();
      expect(encoder).toBeInstanceOf(TextEncoder);
      expect(decoder).toBeInstanceOf(TextDecoder);
    });

    it("should have atob/btoa available", () => {
      expect(atob).toBeDefined();
      expect(btoa).toBeDefined();
    });
  });

  describe("Web Crypto API - ECDSA", () => {
    it("should support ECDSA P-256 sign/verify", async () => {
      const keyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      );

      const data = new TextEncoder().encode("test data for signing");
      const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        keyPair.privateKey,
        data
      );

      const valid = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        keyPair.publicKey,
        signature,
        data
      );

      expect(valid).toBe(true);
      expect(signature.byteLength).toBeGreaterThan(0);
    });

    it("should support ECDSA P-384 sign/verify", async () => {
      const keyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-384" },
        true,
        ["sign", "verify"]
      );

      const data = new TextEncoder().encode("test data");
      const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-384" },
        keyPair.privateKey,
        data
      );

      const valid = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-384" },
        keyPair.publicKey,
        signature,
        data
      );

      expect(valid).toBe(true);
    });

    it("should support ECDSA P-521 sign/verify", async () => {
      const keyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-521" },
        true,
        ["sign", "verify"]
      );

      const data = new TextEncoder().encode("test");
      const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-512" },
        keyPair.privateKey,
        data
      );

      const valid = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-512" },
        keyPair.publicKey,
        signature,
        data
      );

      expect(valid).toBe(true);
    });

    it("should reject invalid ECDSA signatures", async () => {
      const keyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      );

      const data = new TextEncoder().encode("test data");
      const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        keyPair.privateKey,
        data
      );

      const tamperedData = new TextEncoder().encode("tampered data");
      const valid = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        keyPair.publicKey,
        signature,
        tamperedData
      );

      expect(valid).toBe(false);
    });
  });

  describe("Web Crypto API - RSA", () => {
    it("should support RSA-PSS sign/verify", async () => {
      const keyPair = await crypto.subtle.generateKey(
        {
          name: "RSA-PSS",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["sign", "verify"]
      );

      const data = new TextEncoder().encode("test data");
      const signature = await crypto.subtle.sign(
        { name: "RSA-PSS", saltLength: 32 },
        keyPair.privateKey,
        data
      );

      const valid = await crypto.subtle.verify(
        { name: "RSA-PSS", saltLength: 32 },
        keyPair.publicKey,
        signature,
        data
      );

      expect(valid).toBe(true);
      expect(signature.byteLength).toBe(256);
    });

    it("should support RSASSA-PKCS1-v1_5 sign/verify", async () => {
      const keyPair = await crypto.subtle.generateKey(
        {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["sign", "verify"]
      );

      const data = new TextEncoder().encode("test data");
      const signature = await crypto.subtle.sign(
        { name: "RSASSA-PKCS1-v1_5" },
        keyPair.privateKey,
        data
      );

      const valid = await crypto.subtle.verify(
        { name: "RSASSA-PKCS1-v1_5" },
        keyPair.publicKey,
        signature,
        data
      );

      expect(valid).toBe(true);
    });
  });

  describe("Web Crypto API - Hashing", () => {
    it("should support SHA-256 hashing", async () => {
      const data = new TextEncoder().encode("test data");
      const hash = await crypto.subtle.digest("SHA-256", data);

      expect(hash).toBeInstanceOf(ArrayBuffer);
      expect(hash.byteLength).toBe(32);
    });

    it("should support SHA-384 hashing", async () => {
      const data = new TextEncoder().encode("test data");
      const hash = await crypto.subtle.digest("SHA-384", data);

      expect(hash).toBeInstanceOf(ArrayBuffer);
      expect(hash.byteLength).toBe(48);
    });

    it("should support SHA-512 hashing", async () => {
      const data = new TextEncoder().encode("test data");
      const hash = await crypto.subtle.digest("SHA-512", data);

      expect(hash).toBeInstanceOf(ArrayBuffer);
      expect(hash.byteLength).toBe(64);
    });

    it("should produce consistent hashes", async () => {
      const data = new TextEncoder().encode("consistent data");
      const hash1 = await crypto.subtle.digest("SHA-256", data);
      const hash2 = await crypto.subtle.digest("SHA-256", data);

      const arr1 = new Uint8Array(hash1);
      const arr2 = new Uint8Array(hash2);

      expect(uint8ArrayEqual(arr1, arr2)).toBe(true);
    });
  });

  describe("Web Crypto API - Key Operations", () => {
    it("should support SPKI key export/import", async () => {
      const keyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      );

      const exported = await crypto.subtle.exportKey("spki", keyPair.publicKey);
      const imported = await crypto.subtle.importKey(
        "spki",
        exported,
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["verify"]
      );

      expect(imported).toBeDefined();
      expect(imported.type).toBe("public");
      expect(exported.byteLength).toBeGreaterThan(0);
    });
  });

  describe("Encoding - Base64", () => {
    it("should encode and decode base64", () => {
      const original = new Uint8Array([1, 2, 3, 4, 5, 255, 128, 64]);
      const base64 = Uint8ArrayToBase64(original);
      const decoded = base64ToUint8Array(base64);

      expect(decoded).toEqual(original);
    });

    it("should handle empty arrays", () => {
      const empty = new Uint8Array([]);
      const base64 = Uint8ArrayToBase64(empty);
      const decoded = base64ToUint8Array(base64);

      expect(base64).toBe("");
      expect(decoded.length).toBe(0);
    });

    it("should handle base64url encoding", () => {
      const base64url = "SGVsbG8gV29ybGQ";
      const decoded = base64UrlToUint8Array(base64url);
      const expected = stringToUint8Array("Hello World");

      expect(decoded).toEqual(expected);
    });

    it("should handle base64url with padding", () => {
      const base64url = "AQIDBAU";
      const decoded = base64UrlToUint8Array(base64url);

      expect(decoded.length).toBeGreaterThan(0);
      expect(decoded[0]).toBe(1);
    });

  });

  describe("Encoding - Hex", () => {
    it("should encode and decode hex", () => {
      const original = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
      const hex = Uint8ArrayToHex(original);
      const decoded = hexToUint8Array(hex);

      expect(hex).toBe("0123456789abcdef");
      expect(decoded).toEqual(original);
    });

    it("should handle single-digit hex values", () => {
      const original = new Uint8Array([0x00, 0x01, 0x0f]);
      const hex = Uint8ArrayToHex(original);

      expect(hex).toBe("00010f");
    });

    it("should throw on invalid hex strings", () => {
      expect(() => hexToUint8Array("abc")).toThrow("even length");
    });
  });

  describe("Encoding - UTF-8", () => {
    it("should convert string to Uint8Array and back", () => {
      const original = "Hello World!";
      const uint8Array = stringToUint8Array(original);
      const decoded = Uint8ArrayToString(uint8Array);

      expect(decoded).toBe(original);
    });

    it("should handle Unicode characters", () => {
      const original = "Hello 🌍 World! 🔐";
      const uint8Array = stringToUint8Array(original);
      const decoded = Uint8ArrayToString(uint8Array);

      expect(decoded).toBe(original);
      expect(uint8Array.length).toBeGreaterThan(original.length);
    });

    it("should handle empty strings", () => {
      const empty = "";
      const uint8Array = stringToUint8Array(empty);
      const decoded = Uint8ArrayToString(uint8Array);

      expect(uint8Array.length).toBe(0);
      expect(decoded).toBe("");
    });
  });

  describe("Encoding - Utilities", () => {
    it("should compare Uint8Arrays for equality", () => {
      const arr1 = new Uint8Array([1, 2, 3, 4, 5]);
      const arr2 = new Uint8Array([1, 2, 3, 4, 5]);
      const arr3 = new Uint8Array([1, 2, 3, 4, 6]);

      expect(uint8ArrayEqual(arr1, arr2)).toBe(true);
      expect(uint8ArrayEqual(arr1, arr3)).toBe(false);
    });

    it("should detect length differences", () => {
      const arr1 = new Uint8Array([1, 2, 3]);
      const arr2 = new Uint8Array([1, 2, 3, 4]);

      expect(uint8ArrayEqual(arr1, arr2)).toBe(false);
    });
  });

  describe("PEM Encoding", () => {
    it("should convert PEM to DER", () => {
      const pem = `-----BEGIN CERTIFICATE-----
SGVsbG8gV29ybGQ=
-----END CERTIFICATE-----`;

      const der = toDER(pem);
      const expected = stringToUint8Array("Hello World");

      expect(der).toEqual(expected);
    });

    it("should convert DER to PEM", () => {
      const der = stringToUint8Array("Hello World");
      const pem = fromDER(der, "CERTIFICATE");

      expect(pem).toContain("-----BEGIN CERTIFICATE-----");
      expect(pem).toContain("-----END CERTIFICATE-----");
      expect(pem).toContain("SGVsbG8g");
      expect(pem.endsWith("\n")).toBe(true);
    });

    it("should handle custom PEM types", () => {
      const der = new Uint8Array([1, 2, 3]);
      const pem = fromDER(der, "PUBLIC KEY");

      expect(pem).toContain("-----BEGIN PUBLIC KEY-----");
      expect(pem).toContain("-----END PUBLIC KEY-----");
    });

    it("should wrap PEM at 64 characters", () => {
      const longData = new Uint8Array(100);
      for (let i = 0; i < 100; i++) {
        longData[i] = i % 256;
      }

      const pem = fromDER(longData);
      const lines = pem.split("\n");

      for (const line of lines) {
        if (!line.startsWith("-----")) {
          expect(line.length).toBeLessThanOrEqual(64);
        }
      }
    });
  });

  describe("Canonical JSON", () => {
    it("should canonicalize simple objects", () => {
      const obj = { b: 2, a: 1 };
      const canonical = canonicalize(obj);

      expect(canonical).toBe('{"a":1,"b":2}');
    });

    it("should sort keys lexically", () => {
      const obj = { z: 1, a: 2, m: 3 };
      const canonical = canonicalize(obj);

      expect(canonical).toBe('{"a":2,"m":3,"z":1}');
    });

    it("should handle nested objects", () => {
      const obj = { outer: { b: 2, a: 1 }, simple: true };
      const canonical = canonicalize(obj);

      expect(canonical).toBe('{"outer":{"a":1,"b":2},"simple":true}');
    });

    it("should handle arrays", () => {
      const obj = { array: [3, 1, 2], key: "value" };
      const canonical = canonicalize(obj);

      expect(canonical).toBe('{"array":[3,1,2],"key":"value"}');
    });

    it("should escape strings correctly", () => {
      const obj = { text: 'hello "world"' };
      const canonical = canonicalize(obj);

      expect(canonical).toBe('{"text":"hello \\"world\\""}');
    });

    it("should handle backslashes", () => {
      const obj = { path: "C:\\Windows\\System32" };
      const canonical = canonicalize(obj);

      expect(canonical).toBe('{"path":"C:\\\\Windows\\\\System32"}');
    });

    it("should handle booleans and null", () => {
      const obj = { bool: true, nothing: null, flag: false };
      const canonical = canonicalize(obj);

      expect(canonical).toBe('{"bool":true,"flag":false,"nothing":null}');
    });
  });

  describe("ByteStream", () => {
    it("should create empty stream", () => {
      const stream = new ByteStream();

      expect(stream.length).toBe(0);
      expect(stream.position).toBe(0);
      expect(stream.buffer.length).toBe(0);
    });

    it("should append single bytes", () => {
      const stream = new ByteStream();
      stream.appendChar(0x41);
      stream.appendChar(0x42);
      stream.appendChar(0x43);

      expect(stream.position).toBe(3);
      expect(stream.buffer).toEqual(new Uint8Array([0x41, 0x42, 0x43]));
    });

    it("should append Uint8Array views", () => {
      const stream = new ByteStream();
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      stream.appendView(data);

      expect(stream.position).toBe(5);
      expect(stream.buffer).toEqual(data);
    });

    it("should append uint16 values", () => {
      const stream = new ByteStream();
      stream.appendUint16(0x1234);

      expect(stream.position).toBe(2);
      expect(stream.buffer[0]).toBe(0x12);
      expect(stream.buffer[1]).toBe(0x34);
    });

    it("should append uint24 values", () => {
      const stream = new ByteStream();
      stream.appendUint24(0x123456);

      expect(stream.position).toBe(3);
      expect(stream.buffer[0]).toBe(0x12);
      expect(stream.buffer[1]).toBe(0x34);
      expect(stream.buffer[2]).toBe(0x56);
    });

    it("should read blocks", () => {
      const stream = new ByteStream();
      stream.appendView(new Uint8Array([1, 2, 3, 4, 5]));
      stream.seek(0);

      const block = stream.getBlock(3);

      expect(block).toEqual(new Uint8Array([1, 2, 3]));
      expect(stream.position).toBe(3);
    });

    it("should read uint8", () => {
      const stream = new ByteStream();
      stream.appendChar(0xff);
      stream.seek(0);

      const value = stream.getUint8();

      expect(value).toBe(0xff);
      expect(stream.position).toBe(1);
    });

    it("should read uint16", () => {
      const stream = new ByteStream();
      stream.appendUint16(0x1234);
      stream.seek(0);

      const value = stream.getUint16();

      expect(value).toBe(0x1234);
      expect(stream.position).toBe(2);
    });

    it("should slice data", () => {
      const stream = new ByteStream();
      stream.appendView(new Uint8Array([1, 2, 3, 4, 5]));

      const slice = stream.slice(1, 3);

      expect(slice).toEqual(new Uint8Array([2, 3, 4]));
    });

    it("should grow buffer automatically", () => {
      const stream = new ByteStream();
      const largeData = new Uint8Array(2000);
      largeData.fill(0x42);

      stream.appendView(largeData);

      expect(stream.position).toBe(2000);
      expect(stream.buffer.length).toBe(2000);
    });

    it("should throw on slice beyond allocated length", () => {
      const buffer = new Uint8Array(10);
      const stream = new ByteStream(buffer);

      expect(() => stream.slice(0, 20)).toThrow();
    });
  });

  describe("ASN.1 Parsing", () => {
    it("should parse simple ASN.1 sequences", () => {
      const sequence = new Uint8Array([
        0x30, 0x06,
        0x02, 0x01, 0x01,
        0x02, 0x01, 0x02
      ]);

      const obj = ASN1Obj.parseBuffer(sequence);

      expect(obj.tag.constructed).toBe(true);
      expect(obj.subs.length).toBe(2);
    });

    it("should parse ASN.1 integers", () => {
      const integer = new Uint8Array([0x02, 0x01, 0x2A]);
      const obj = ASN1Obj.parseBuffer(integer);

      expect(obj.toInteger()).toBe(42n);
    });

    it("should parse ASN.1 booleans", () => {
      const boolTrue = new Uint8Array([0x01, 0x01, 0xFF]);
      const boolFalse = new Uint8Array([0x01, 0x01, 0x00]);

      const objTrue = ASN1Obj.parseBuffer(boolTrue);
      const objFalse = ASN1Obj.parseBuffer(boolFalse);

      expect(objTrue.toBoolean()).toBe(true);
      expect(objFalse.toBoolean()).toBe(false);
    });
  });

  describe("Crypto Wrapper Functions", () => {
    it("should import ECDSA P-256 keys from PEM", async () => {
      const keyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      );

      const spki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
      const pem = fromDER(new Uint8Array(spki), "PUBLIC KEY");

      const importedKey = await importKey("ECDSA", "P-256", pem);

      expect(importedKey).toBeDefined();
      expect(importedKey.type).toBe("public");
      expect(importedKey.algorithm.name).toBe("ECDSA");
    });

    it("should import ECDSA P-384 keys from PEM", async () => {
      const keyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-384" },
        true,
        ["sign", "verify"]
      );

      const spki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
      const pem = fromDER(new Uint8Array(spki), "PUBLIC KEY");

      const importedKey = await importKey("ECDSA", "P-384", pem);

      expect(importedKey).toBeDefined();
      expect(importedKey.type).toBe("public");
    });

    it("should import RSA keys from PEM", async () => {
      const keyPair = await crypto.subtle.generateKey(
        {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["sign", "verify"]
      );

      const spki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
      const pem = fromDER(new Uint8Array(spki), "PUBLIC KEY");

      const importedKey = await importKey("RSA", "rsassa-pkcs1-v1_5-sha256", pem);

      expect(importedKey).toBeDefined();
      expect(importedKey.type).toBe("public");
    });
  });
});
