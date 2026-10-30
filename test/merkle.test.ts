import { readFileSync } from "fs";
import { join } from "path";
import { describe, expect, it } from "vitest";

import { base64ToUint8Array, hexToUint8Array, stringToUint8Array, Uint8ArrayToHex } from "../src/encoding.js";
import { hashChildren, hashLeaf, rootHash, verifyConsistencyProof, verifyInclusionProof } from "../src/merkle.js";

const fixture = (name: string) => JSON.parse(readFileSync(join(__dirname, "fixtures/merkle", name), "utf8"));
const b64 = (s: string | null) => (s === null ? new Uint8Array(0) : base64ToUint8Array(s));
const proofOf = (p: string[] | null) => (p ?? []).map(b64);

// Vectors from transparency-dev/merkle (rfc6962_test.go, testonly/constants.go, testdata/).
describe("RFC 6962 hashing", () => {
  it("matches the leaf and node vectors", async () => {
    expect(Uint8ArrayToHex(await hashLeaf(new Uint8Array(0)))).toBe(
      "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    );
    expect(Uint8ArrayToHex(await hashLeaf(stringToUint8Array("L123456")))).toBe(
      "395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56",
    );
    expect(Uint8ArrayToHex(await hashChildren(stringToUint8Array("N123"), stringToUint8Array("N456")))).toBe(
      "aa217fe888e47007fa15edab33c2b492a722cb106c64667fc2b044444de66bbb",
    );
  });

  it("computes the root of trees of size 0 to 8", async () => {
    const { leafInputs, rootHashes } = fixture("trees.json") as { leafInputs: string[]; rootHashes: string[] };
    const leaves = await Promise.all(leafInputs.map((hex) => hashLeaf(hexToUint8Array(hex))));
    for (let size = 0; size <= leaves.length; size++) {
      expect(Uint8ArrayToHex(await rootHash(leaves.slice(0, size)))).toBe(rootHashes[size]);
    }
  });
});

type Inclusion = {
  leafIdx: number;
  treeSize: number;
  root: string;
  leafHash: string;
  proof: string[] | null;
  desc: string;
  wantErr: boolean;
  file: string;
};
type Consistency = {
  size1: number;
  size2: number;
  root1: string;
  root2: string;
  proof: string[] | null;
  desc: string;
  wantErr: boolean;
  file: string;
};

describe("verifyInclusionProof", () => {
  for (const p of fixture("inclusion.json") as Inclusion[]) {
    it(`${p.file}: ${p.desc}`, async () => {
      expect(await verifyInclusionProof(b64(p.leafHash), p.leafIdx, p.treeSize, b64(p.root), proofOf(p.proof))).toBe(
        !p.wantErr,
      );
    });
  }

  it("rejects an index or size outside the safe range", async () => {
    const h = new Uint8Array(32);
    expect(await verifyInclusionProof(h, -1, 1, h, [])).toBe(false);
    expect(await verifyInclusionProof(h, 0, 2 ** 53, h, [])).toBe(false);
    expect(await verifyInclusionProof(h, 1.5, 4, h, [h, h])).toBe(false);
  });
});

describe("verifyConsistencyProof", () => {
  for (const p of fixture("consistency.json") as Consistency[]) {
    it(`${p.file}: ${p.desc}`, async () => {
      expect(await verifyConsistencyProof(p.size1, p.size2, b64(p.root1), b64(p.root2), proofOf(p.proof))).toBe(
        !p.wantErr,
      );
    });
  }
});

// Provers written from the recursive definitions in RFC 6962 §2.1.1 and
// §2.1.2, independent of the iterative verifier they cross-check.
const split = (n: number) => 2 ** Math.floor(Math.log2(n - 1));
async function mth(d: Uint8Array[]): Promise<Uint8Array> {
  if (d.length === 1) return d[0];
  const k = split(d.length);
  return hashChildren(await mth(d.slice(0, k)), await mth(d.slice(k)));
}
async function inclusionPath(m: number, d: Uint8Array[]): Promise<Uint8Array[]> {
  if (d.length === 1) return [];
  const k = split(d.length);
  return m < k
    ? [...(await inclusionPath(m, d.slice(0, k))), await mth(d.slice(k))]
    : [...(await inclusionPath(m - k, d.slice(k))), await mth(d.slice(0, k))];
}
async function subproof(m: number, d: Uint8Array[], b: boolean): Promise<Uint8Array[]> {
  if (m === d.length) return b ? [] : [await mth(d)];
  const k = split(d.length);
  return m <= k
    ? [...(await subproof(m, d.slice(0, k), b)), await mth(d.slice(k))]
    : [...(await subproof(m - k, d.slice(k), false)), await mth(d.slice(0, k))];
}

describe("against the RFC 6962 recursive definitions", () => {
  const leaves: Uint8Array[] = [];
  const roots: Uint8Array[] = [];
  const SIZE = 64;

  it("agrees on every root and verifies every inclusion proof up to size 64", async () => {
    for (let i = 0; i < SIZE; i++) leaves.push(await hashLeaf(new Uint8Array([i, i * 7, i * 13])));
    for (let n = 1; n <= SIZE; n++) {
      const tree = leaves.slice(0, n);
      roots[n] = await mth(tree);
      expect(roots[n]).toEqual(await rootHash(tree));
      for (let m = 0; m < n; m++) {
        expect(await verifyInclusionProof(leaves[m], m, n, roots[n], await inclusionPath(m, tree))).toBe(true);
      }
    }
  });

  it("rejects a proof replayed at another index or tree size", async () => {
    for (const n of [2, 3, 5, 8, 13, 31, 32, 64]) {
      const tree = leaves.slice(0, n);
      for (const m of [0, Math.floor(n / 2), n - 1]) {
        const path = await inclusionPath(m, tree);
        for (let other = 0; other < n; other++) {
          if (other !== m) expect(await verifyInclusionProof(leaves[m], other, n, roots[n], path)).toBe(false);
        }
        for (const size of [n - 1, n + 1]) {
          if (size >= 1 && size <= SIZE && m < size) {
            expect(await verifyInclusionProof(leaves[m], m, size, roots[size], path)).toBe(false);
          }
        }
        if (path.length > 1) {
          const swapped = [path[1], path[0], ...path.slice(2)];
          expect(await verifyInclusionProof(leaves[m], m, n, roots[n], swapped)).toBe(false);
        }
      }
    }
  });

  it("verifies every consistency proof up to size 32 and rejects the wrong roots", async () => {
    for (let n = 1; n <= 32; n++) {
      for (let m = 1; m <= n; m++) {
        const proof = await subproof(m, leaves.slice(0, n), true);
        expect(await verifyConsistencyProof(m, n, roots[m], roots[n], proof)).toBe(true);
        if (m < n) {
          expect(await verifyConsistencyProof(m, n, roots[n], roots[m], proof)).toBe(false);
          expect(await verifyConsistencyProof(m, n, roots[m], roots[m], proof)).toBe(false);
        }
      }
    }
  });
});

describe("tree shape", () => {
  it("separates leaves from interior nodes", async () => {
    const left = await hashLeaf(stringToUint8Array("a"));
    const right = await hashLeaf(stringToUint8Array("b"));
    const node = await hashChildren(left, right);
    const asLeaf = await hashLeaf(new Uint8Array([...left, ...right]));
    expect(asLeaf).not.toEqual(node);
    // A forged proof presenting the node's preimage as the leaf of a size-1 tree.
    expect(await verifyInclusionProof(asLeaf, 0, 1, node, [])).toBe(false);
  });

  it("does not duplicate an odd last leaf", async () => {
    const [a, b, c] = await Promise.all(["a", "b", "c"].map((s) => hashLeaf(stringToUint8Array(s))));
    expect(await rootHash([a, b, c])).not.toEqual(await rootHash([a, b, c, c]));
  });
});
