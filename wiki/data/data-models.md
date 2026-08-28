---
title: Data Models
last_reviewed: 2026-08-28
tags: [data, models, ecies, key-structures]
folder: data
sources:
  - code:key_pair.go
  - code:ecies.go
agent_routing:
  code_change_relevance: conditional
  task_intents: [data-model-change]
  applies_to_paths: []
  applies_to_symbols: [PublicKey, PrivateKey]
---

# Data Models

## Key structures

### PublicKey

The `PublicKey` type represents an elliptic curve public key:

```go
type PublicKey struct {
    elliptic.Curve
    X *big.Int
    Y *big.Int
}
```

- `Curve` -- the elliptic curve (default: secp256r1 / P256)
- `X` -- the X coordinate of the public key point
- `Y` -- the Y coordinate of the public key point

### PrivateKey

The `PrivateKey` type represents an elliptic curve private key:

```go
type PrivateKey struct {
    *PublicKey
    D *big.Int
}
```

- `PublicKey` -- the corresponding public key (embedded)
- `D` -- the private scalar value

## Ciphertext structure

An encrypted message (ciphertext) is a concatenation of:

1. **Ephemeral public key** (uncompressed point: 1 + 2 * byteLen bytes, e.g., 65 bytes for P256)
2. **Encrypted message** (ciphertext from AES-CBC or AES-GCM)
3. **MAC** (HMAC output, e.g., 32 bytes for SHA256)

## Data flow

### Encryption flow

1. Ephemeral key pair generated
2. Shared secret derived via ECSVDP-DH (key agreement)
3. KDF derives encryption key and MAC key from shared secret + ephemeral public key
4. Message encrypted with symmetric cipher using encryption key
5. HMAC computed over ciphertext using MAC key
6. Output: ephemeral public key || ciphertext || MAC

### Decryption flow

1. Ephemeral public key extracted from ciphertext
2. Shared secret derived via ECSVDP-DH
3. KDF derives encryption key and MAC key
4. MAC validated
5. Ciphertext decrypted

## Source References

- `code:key_pair.go` -- contributed key data structures.
- `code:ecies.go` -- contributed encryption/decryption data flow.
