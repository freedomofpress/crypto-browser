import { describe, expect, it } from "vitest";
import { createHash } from "crypto";
import { readdirSync, readFileSync } from "fs";
import { join } from "path";

import { canonicalizeJCS, canonicalizeOLPC } from "../src/canonicalize.js";

const dir = join(__dirname, "fixtures/canonical-json");

// Generated with the olpc-cjson crate (webcat-spec vectors/canonical-json.json).
describe("canonicalizeOLPC", () => {
  type Vector = { name: string; input: unknown; canonical_hex?: string; sha256?: string; error?: boolean };
  const { vectors } = JSON.parse(readFileSync(join(dir, "olpc.json"), "utf8")) as { vectors: Vector[] };
  for (const v of vectors) {
    it(v.name, () => {
      if (v.error) {
        expect(() => canonicalizeOLPC(v.input)).toThrow(TypeError);
        return;
      }
      const bytes = Buffer.from(canonicalizeOLPC(v.input), "utf8");
      expect(bytes.toString("hex")).toBe(v.canonical_hex);
      expect(createHash("sha256").update(bytes).digest("hex")).toBe(v.sha256);
    });
  }
  it("sorts keys by code point, shorter prefix first", () => {
    const out = canonicalizeOLPC({ "\u{10000}": 1, "\uFFFF": 2, ab: 3, a: 4, b: 5 });
    expect(out).toBe('{"a":4,"ab":3,"b":5,"\uFFFF":2,"\u{10000}":1}');
  });
});

// Official RFC 8785 vectors from cyberphone/json-canonicalization testdata.
describe("canonicalizeJCS", () => {
  for (const file of readdirSync(join(dir, "jcs/input"))) {
    it(file, () => {
      const input = JSON.parse(readFileSync(join(dir, "jcs/input", file), "utf8"));
      const expected = readFileSync(join(dir, "jcs/output", file), "utf8");
      expect(canonicalizeJCS(input)).toBe(expected);
    });
  }
  it("rejects non-finite numbers and undefined", () => {
    expect(() => canonicalizeJCS(NaN)).toThrow(TypeError);
    expect(() => canonicalizeJCS({ a: undefined })).toThrow(TypeError);
  });
});

// The dialects coincide on the subset both Rekor and TUF actually emit: ASCII
// strings without control characters, safe integers, booleans, null, BMP keys.
describe("canonicalizeOLPC and canonicalizeJCS", () => {
  it("agree on a Rekor signed entry timestamp payload", () => {
    const payload = {
      body: "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIn0=",
      integratedTime: 1683317662,
      logIndex: 19808100,
      logID: "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
    };
    expect(canonicalizeOLPC(payload)).toBe(canonicalizeJCS(payload));
    expect(canonicalizeOLPC(payload)).toBe(
      '{"body":"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIn0=","integratedTime":1683317662,"logID":"c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d","logIndex":19808100}',
    );
  });

  it("agree on TUF-style metadata with hex keys", () => {
    const signed = {
      _type: "root",
      spec_version: "1.0",
      version: 12,
      expires: "2026-04-01T00:00:00Z",
      consistent_snapshot: true,
      keys: { "4c3b": { keytype: "ecdsa-sha2-nistp256", scheme: "ecdsa-sha2-nistp256", keyval: { public: "04cbc5" } } },
      roles: { root: { keyids: ["4c3b"], threshold: 1 }, targets: { keyids: [], threshold: 1 } },
      custom: null,
    };
    expect(canonicalizeOLPC(signed)).toBe(canonicalizeJCS(signed));
  });

  it("differ on control characters", () => {
    expect(canonicalizeOLPC({ s: "a\nb" })).toBe('{"s":"a\nb"}');
    expect(canonicalizeJCS({ s: "a\nb" })).toBe('{"s":"a\\nb"}');
  });

  it("differ on keys above U+FFFF", () => {
    const obj = { "￿": 1, "\u{10000}": 2 };
    expect(canonicalizeOLPC(obj)).toBe('{"￿":1,"\u{10000}":2}');
    expect(canonicalizeJCS(obj)).toBe('{"\u{10000}":2,"￿":1}');
  });

  it("differ on floats and large integers", () => {
    expect(() => canonicalizeOLPC({ n: 1.5 })).toThrow(TypeError);
    expect(canonicalizeJCS({ n: 1.5 })).toBe('{"n":1.5}');
    expect(() => canonicalizeOLPC({ n: 1e21 })).toThrow(TypeError);
    expect(canonicalizeJCS({ n: 1e21 })).toBe('{"n":1e+21}');
  });
});
