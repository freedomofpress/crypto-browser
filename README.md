# crypto-browser

[![CI](https://github.com/freedomofpress/crypto-browser/actions/workflows/ci.yml/badge.svg)](https://github.com/freedomofpress/crypto-browser/actions/workflows/ci.yml)

Browser-compatible cryptography utilities for Sigstore and TUF verification.

Used by [tuf-browser](https://github.com/freedomofpress/tuf-browser) and [sigstore-browser](https://github.com/freedomofpress/sigstore-browser).

> [!CAUTION]
> This library has not received an independent security audit. Maintenance is performed by volunteers, and the project is not officially supported or endorsed by the Freedom of the Press Foundation.

## Features

This package provides shared cryptographic and encoding utilities used across multiple Sigstore browser implementations:

### ASN.1 Parsing & Encoding
- **ASN1Obj**: Parse and encode DER-encoded ASN.1 structures
- **ASN1Tag**: Handle ASN.1 tags and type checking
- **Length encoding/decoding**: DER length format support
- **Type parsers**: Extract integers, OIDs, dates, bit strings, booleans from ASN.1

### X.509 Certificate Support
- **X509Certificate**: Parse and verify X.509 certificates (PEM or DER)
- **X.509 Extensions**: Support for standard and Fulcio-specific extensions
  - Basic Constraints
  - Key Usage
  - Subject Alternative Name
  - Authority/Subject Key Identifiers
  - Signed Certificate Timestamps (SCT)
  - Fulcio Issuer extensions (v1 & v2)

### Encoding Utilities
- **Base64**: Encode/decode with standard and URL-safe variants
- **Hex**: Encode/decode hexadecimal strings
- **PEM**: Convert between PEM and DER formats
- **UTF-8**: String to Uint8Array conversion
- **Constant-time comparison**: Timing-attack resistant byte comparison

### Cryptographic Operations
- **Key import**: Support for ECDSA (P-256/P-384/P-521), Ed25519, and RSA keys
- **Signature verification**: Verify signatures using Web Crypto API
  - ECDSA with SHA-256/384/512
  - Ed25519
  - RSA-PSS and RSASSA-PKCS1-v1_5
- **Digest verification**: ECDSA signature verification over pre-computed digests (using @noble/curves)
- **Certificate chain verification**: Verify certificate chains against trusted CAs with timestamp validation
- **PKCS#1 to SPKI conversion**: Convert RSA keys for Web Crypto compatibility

### Additional Utilities
- **ByteStream**: Efficient byte buffer with auto-growing allocation
- **Canonical JSON**: TUF-compliant canonical JSON encoding
- **OID mappings**: Mappings for signature algorithms, hash algorithms, and ECDSA curves

## Installation

```bash
npm install crypto-browser
```

## Usage

### Parse and verify an X.509 certificate

```typescript
import { X509Certificate } from 'crypto-browser';

const cert = X509Certificate.parse(pemOrDerBytes);
console.log(cert.subject);
console.log(cert.notBefore, cert.notAfter);

const isValid = await cert.verify(issuerCert);
```

### Import a public key and verify a signature

```typescript
import { importKey, verifySignature } from 'crypto-browser';

const publicKey = await importKey('ECDSA', 'P-256', pemKey);
const isValid = await verifySignature(publicKey, message, signature, 'sha256');
```

### Verify a certificate chain

```typescript
import { verifyCertificateChain, X509Certificate } from 'crypto-browser';

const leafCert = X509Certificate.parse(certBytes);
const verifiedChain = await verifyCertificateChain(
  new Date(),
  leafCert,
  certificateAuthorities
);
```

### Parse ASN.1 structures

```typescript
import { ASN1Obj } from 'crypto-browser';

const asn1 = ASN1Obj.parseBuffer(derBytes);
const oid = asn1.subs[0].toOID();
const integer = asn1.subs[1].toInteger();
```

### Encode/decode utilities

```typescript
import {
  base64ToUint8Array,
  Uint8ArrayToHex,
  toDER,
  fromDER,
} from 'crypto-browser';

const bytes = base64ToUint8Array('SGVsbG8=');
const hex = Uint8ArrayToHex(bytes);
const der = toDER(pemCertificate);
const pem = fromDER(derBytes, 'CERTIFICATE');
```

## Dependencies

- `@noble/curves`: Used for low-level ECDSA verification over pre-computed digests

## Structure

```
crypto-browser/
    asn1/           # ASN.1 parsing and encoding
    x509/           # X.509 certificate and extension support
    encoding.ts     # Base64, hex, UTF-8 encoding
    pem.ts          # PEM format conversion
    stream.ts       # ByteStream utility
    crypto.ts       # Cryptographic operations
    oid.ts          # OID mappings
    canonicalize.ts # Canonical JSON
    interfaces.ts   # TypeScript interfaces and enums
```

## Development

```bash
# Install dependencies
npm install

# Build the project
npm run build
```

## License

Apache-2.0 - see [LICENSE](LICENSE) file for details.

## Acknowledgments

This package provides browser-compatible versions of cryptographic utilities from the Sigstore and TUF ecosystems. All code is licensed under Apache-2.0.

**Primary Sources:**
- [sigstore-js](https://github.com/sigstore/sigstore-js) - Core ASN.1, X.509, and crypto utilities
- [tuf-js](https://github.com/theupdateframework/tuf-js) - Canonical JSON implementation

All files maintain their original copyright headers. 

