// RFC 6962 Merkle trees over SHA-256, as used by Rekor, Sigsum and CometBFT.
import { sha256 } from "./crypto.js";
import { concatBytes, uint8ArrayEqual } from "./encoding.js";

const LEAF_PREFIX = new Uint8Array([0x00]);
const NODE_PREFIX = new Uint8Array([0x01]);

export const hashLeaf = (data: Uint8Array): Promise<Uint8Array> => sha256(concatBytes(LEAF_PREFIX, data));

export const hashChildren = (left: Uint8Array, right: Uint8Array): Promise<Uint8Array> =>
  sha256(concatBytes(NODE_PREFIX, left, right));

// Largest power of two strictly below n.
function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

// Root of a tree over already hashed leaves (RFC 6962 §2.1); the empty tree
// hashes to SHA-256 of nothing.
export async function rootHash(leafHashes: Uint8Array[]): Promise<Uint8Array> {
  if (leafHashes.length === 0) return sha256(new Uint8Array(0));
  if (leafHashes.length === 1) return leafHashes[0];
  const k = splitPoint(leafHashes.length);
  return hashChildren(await rootHash(leafHashes.slice(0, k)), await rootHash(leafHashes.slice(k)));
}

const isIndex = (n: number) => Number.isSafeInteger(n) && n >= 0;

const bitLength = (n: number): number => (n === 0 ? 0 : BigInt(n).toString(2).length);
const popCount = (n: number): number => BigInt(n).toString(2).split("1").length - 1;
const trailingZeros = (n: number): number =>
  BigInt(n).toString(2).length - BigInt(n).toString(2).replace(/0+$/, "").length;

// Splits an inclusion proof for leaf `index` in a tree of `size` into the
// hashes whose side the index bits decide (inner) and the hashes that always
// sit on the left (border): RFC 9162 §2.1.3.2.
function decompose(index: number, size: number): { inner: number; border: number } {
  const inner = bitLength(Number(BigInt(index) ^ BigInt(size - 1)));
  return { inner, border: popCount(Math.floor(index / 2 ** inner)) };
}

// Verifies that `leafHash` sits at `index` in a tree of `size` with `root`,
// given the sibling hashes from the leaf up (RFC 9162 §2.1.3.2).
export async function verifyInclusionProof(
  leafHash: Uint8Array,
  index: number,
  size: number,
  root: Uint8Array,
  proof: Uint8Array[],
): Promise<boolean> {
  if (!isIndex(index) || !isIndex(size) || index >= size || leafHash.length !== 32) {
    return false;
  }
  const { inner, border } = decompose(index, size);
  if (proof.length !== inner + border) return false;
  let hash = leafHash;
  for (let i = 0; i < inner; i++) {
    const sibling = proof[i];
    hash = Math.floor(index / 2 ** i) % 2 === 1 ? await hashChildren(sibling, hash) : await hashChildren(hash, sibling);
  }
  for (const sibling of proof.slice(inner)) {
    hash = await hashChildren(sibling, hash);
  }
  return uint8ArrayEqual(hash, root);
}

// Verifies that the tree of `size2` with `root2` extends the tree of `size1`
// with `root1`, given the proof hashes (RFC 9162 §2.1.4.2).
export async function verifyConsistencyProof(
  size1: number,
  size2: number,
  root1: Uint8Array,
  root2: Uint8Array,
  proof: Uint8Array[],
): Promise<boolean> {
  if (!isIndex(size1) || !isIndex(size2) || size1 > size2) {
    return false;
  }
  // A proof from the empty tree proves nothing.
  if (size1 === 0) return false;
  if (size1 === size2) return proof.length === 0 && uint8ArrayEqual(root1, root2);
  // The proof is an inclusion proof of the node covering size1's last leaf,
  // except that a size1 which is a power of two starts from root1 itself.
  const shift = trailingZeros(size1);
  const { inner: innerAll, border } = decompose(size1 - 1, size2);
  const inner = innerAll - shift;
  const start = size1 === 2 ** shift ? 0 : 1;
  if (proof.length !== start + inner + border) return false;
  const seed = start === 0 ? root1 : proof[0];
  const hashes = proof.slice(start);
  const mask = Math.floor((size1 - 1) / 2 ** shift);
  let hash1 = seed;
  let hash2 = seed;
  for (let i = 0; i < inner; i++) {
    const sibling = hashes[i];
    if (Math.floor(mask / 2 ** i) % 2 === 1) {
      hash1 = await hashChildren(sibling, hash1);
      hash2 = await hashChildren(sibling, hash2);
    } else {
      hash2 = await hashChildren(hash2, sibling);
    }
  }
  for (const sibling of hashes.slice(inner)) {
    hash1 = await hashChildren(sibling, hash1);
    hash2 = await hashChildren(sibling, hash2);
  }
  return uint8ArrayEqual(hash1, root1) && uint8ArrayEqual(hash2, root2);
}
