// Real Ed25519 data from test/fixtures/sigstore/rekor2-happy-path.
// The key is the PKIX_ED25519 log key in trusted_root.json. The checkpoint is from the bundle.
// This is a TS module so the browser suite can import it without fs.

export const REKOR2_ED25519_SPKI_BASE64 = "MCowBQYDK2VwAyEAPn+AREHoBaZ7wgS1zBqpxmLSGnyhxXj4lFxSdWVB8o8=";

// A signed note: body, blank line, then "— <origin> <base64(4-byte key hint + 64-byte signature)>".
export const REKOR2_CHECKPOINT_ENVELOPE =
  "log2025-alpha1.rekor.sigstage.dev\n736\nrs1YPY0ydAV0lxgfrq5pE4oRpUJwo3syeps5+eGUTDI=\n\n" +
  "\u2014 log2025-alpha1.rekor.sigstage.dev 8w1amdbj1mjNN674dHAkD92+QZoEgBC7o0mXYSTRluDjQrOPjrps3zQB9ut+ShLepyZPsWBDi5IB3yXyjgjQT6OG9A8=\n";

// Returns the signed bytes and the 64-byte signature.
export function rekor2Checkpoint(base64ToUint8Array: (s: string) => Uint8Array) {
  const [body, signatureLine] = REKOR2_CHECKPOINT_ENVELOPE.split("\n\n");
  const blob = base64ToUint8Array(signatureLine.trim().split(" ").pop()!);
  return { signed: new TextEncoder().encode(body + "\n"), signature: blob.subarray(4) };
}
