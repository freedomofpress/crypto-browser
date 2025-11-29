export enum KeyTypes {
  Ecdsa = "ECDSA",
  Ed25519 = "Ed25519",
  RSA = "RSA",
}

export enum EcdsaTypes {
  P256 = "P-256",
  P384 = "P-384",
  P521 = "P-521",
}

export enum HashAlgorithms {
  SHA256 = "SHA-256",
  SHA384 = "SHA-384",
  SHA512 = "SHA-512",
}

export enum RsaAlgorithms {
  PKCS1v15 = "RSASSA-PKCS1-v1_5",
  PSS = "RSA-PSS",
}

export enum RsaSchemes {
  PKCS1 = "PKCS1",
  RSAPKCS1 = "RSAPKCS1",
}
