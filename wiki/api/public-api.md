---
title: Public API
last_reviewed: 2026-08-28
tags: [api, public, ecies, interfaces]
folder: api
sources:
  - code:ecies.go
  - code:key_pair.go
  - code:curve.go
  - code:key_agreement.go
  - code:key_deviration_function.go
  - code:symmetric_cipher.go
  - code:encode_utils.go
  - code:aes_cbc_pkcs7_cipher.go
  - code:aes_gcm_cipher.go
  - code:ecsvdp_dh_key_agreement.go
  - code:key_deviration_function_1.go
  - code:key_deviration_function_2.go
agent_routing:
  code_change_relevance: conditional
  task_intents: [api-contract-change]
  applies_to_paths: []
  applies_to_symbols: [NewECIES, NewCustomizedECIES, Encrypt, Decrypt, GenerateKey, SetCurve]
---

# Public API

## Types

- **`ECIES`** -- The main ECIES struct holding pluggable components for key agreement, KDF, symmetric cipher, and HMAC hashing.

- **`PublicKey`** -- An elliptic curve public key with `Curve`, `X`, and `Y` fields (embeds `elliptic.Curve`).

- **`PrivateKey`** -- An elliptic curve private key with a `D` field (embeds `*PublicKey`).

## Interfaces

```go
type KeyAgreement interface {
    CalculateAgreement(privateKey *PrivateKey, anotherPublicKey *PublicKey) ([]byte, error)
}

type KeyDerivationFunction interface {
    GenerateKeyBytes(secret []byte, iv []byte, kenBytesLength int) ([]byte, error)
}

type SymmetricCipher interface {
    Encrypt(msg []byte, key []byte) ([]byte, error)
    Decrypt(encMsg []byte, key []byte) ([]byte, error)
}
```

## Constructors

| Function | Description |
| --- | --- |
| `NewECIES() *ECIES` | Creates an ECIES instance with default algorithms (secp256r1, ECSVDP-DH, KDF2-SHA256, HMAC-SHA256, AES-CBC-PKCS7) |
| `NewCustomizedECIES(ka, cipher, kdf, hmacHash, encKeyByteSize, macKeyByteSize) *ECIES` | Creates an ECIES instance with custom components |

## Key management

| Function | Description |
| --- | --- |
| `GenerateKey() (*PrivateKey, error)` | Generates an ECC key pair using crypto/rand |
| `SerializePrivateKey(key *PrivateKey) []byte` | Serializes the private key D value |
| `DeserializePrivateKey(dBytes []byte) *PrivateKey` | Deserializes from D bytes, recomputing the public key |
| `SerializePublicKey(key *PublicKey) []byte` | Serializes public key to uncompressed point bytes |
| `DeserializePublicKey(pointBytes []byte) (*PublicKey, error)` | Deserializes from uncompressed point bytes |
| `DeserializePublicKeyFromCoordinate(x, y string) (*PublicKey, error)` | Deserializes from X,Y coordinate strings |
| `SerializePublicKeyToCoordinate(key *PublicKey) (string, string)` | Serializes to X,Y coordinate strings |

## Encryption/Decryption

| Method | Description |
| --- | --- |
| `ecies.Encrypt(pubkey *PublicKey, msg []byte) ([]byte, error)` | Encrypts a message with the receiver's public key |
| `ecies.Decrypt(privkey *PrivateKey, msg []byte) ([]byte, error)` | Decrypts a message with the receiver's private key |

## Curve configuration

| Function | Description |
| --- | --- |
| `GetCurve() elliptic.Curve` | Returns the current curve |
| `SetCurve(c elliptic.Curve)` | Sets a custom elliptic curve |
| `ClearCurve()` | Resets to the default curve (P256) |
| `GetECPointByteLength() int` | Returns the byte length of an encoded point on the current curve |

## Utility functions

| Function | Description |
| --- | --- |
| `HexEncode(data []byte) string` | Hex-encodes data |
| `HexDecode(s string) ([]byte, error)` | Hex-decodes a string |
| `HexDecodeWithoutError(s string) []byte` | Hex-decodes without returning an error (returns nil on failure) |
| `HmacSha256(data, secret []byte, otherDatas ...[]byte) []byte` | Computes HMAC-SHA256 |
| `Hmac(hash crypto.Hash, data, secret []byte, otherDatas ...[]byte) []byte` | Computes HMAC with a specified hash |

## Default cipher implementations

| Constructor | Type | Description |
| --- | --- | --- |
| `NewAesCbcPkcs7Cipher() *AesCbcPkcs7Cipher` | Default | AES-CBC with PKCS7 padding (zero IV) |
| `NewAesGcmCipher() *AesGcmCipher` | Optional | AES-GCM (12-byte zero nonce) |
| `NewEcsvdpDhKeyAgreement() *EcsvdpDhKeyAgreement` | Default | ECSVDP-DH key agreement |
| `NewKeyDerivationFunction1(hash) *KeyDerivationFunction1` | Optional | KDF1 key derivation |
| `NewKeyDerivationFunction2(hash) *KeyDerivationFunction2` | Default | KDF2 key derivation |

## Source References

- `code:ecies.go` -- contributed ECIES struct, Encrypt/Decrypt, constructors.
- `code:key_pair.go` -- contributed key types and serialize/deserialize functions.
- `code:curve.go` -- contributed curve configuration functions.
- `code:encode_utils.go` -- contributed hex encode/decode functions.
