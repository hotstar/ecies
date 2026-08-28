---
title: Module Structure
last_reviewed: 2026-08-28
tags: [architecture, modules, ecies, structure]
folder: architecture
sources:
  - code:ecies.go
  - code:key_agreement.go
  - code:kdf_utils.go
  - code:symmetric_cipher.go
  - code:key_deviration_function.go
  - code:hmac_utils.go
agent_routing:
  code_change_relevance: conditional
  task_intents: [architecture-change]
  applies_to_paths: []
  applies_to_symbols: []
---

# Module Structure

The library is organized as a single Go package (`ecies`) at the repo root. Components are separated by file according to their role in the ECIES flow.

## Component architecture

The ECIES encryption scheme consists of four pluggable components:

1. **Key Agreement** -- Computes a shared secret between two parties using elliptic curve Diffie-Hellman (ECSVDP-DH per IEEE P1363 7.2.1).
2. **Key Derivation Function (KDF)** -- Derives encryption and MAC keys from the shared secret. Supports KDF1 and KDF2 variants (ISO 18033).
3. **Symmetric Cipher** -- Encrypts and decrypts the message using AES. Supports AES-CBC-PKCS7 (default) and AES-GCM.
4. **MAC** -- Authenticates the ciphertext using HMAC-SHA256.

Each component is defined as a Go interface, allowing developers to substitute their own implementations.

## Data flow

```
Plaintext
   |
   v
[Key Agreement] --> Shared Secret --> [KDF] --> Enc Key + MAC Key
   |                                                    |
   v                                                    v
[Ephemeral Key Pair]                               [Symmetric Cipher] --> Ciphertext
                                                           |
                                                           v
                                                     [HMAC] --> MAC
                                                           |
                                                           v
                                              Ephemeral PubKey + Ciphertext + MAC
```

## Entry points

- `GenerateKey()` -- generates an ECC key pair (entry/go.crypto/rand)
- `NewECIES()` -- creates a default ECIES instance
- `NewCustomizedECIES()` -- creates a customized ECIES instance with user-supplied components
- `Encrypt(pubkey, msg)` -- encrypts a message given a public key
- `Decrypt(privkey, msg)` -- decrypts a message given a private key

## Dependencies

- Standard library: `crypto/aes`, `crypto/cipher`, `crypto/elliptic`, `crypto/rand`, `crypto/hmac`, `crypto/sha256`, `crypto/sha1`, `crypto/sha512`, `encoding/hex`, `math/big`
- Third-party (test only): `github.com/stretchr/testify` v1.8.1

## Source References

- `code:ecies.go` -- contributed ECIES struct and component wiring.
- `code:key_agreement.go` -- contributed KeyAgreement interface.
- `code:kdf_utils.go` -- contributed KDF implementation.
- `code:symmetric_cipher.go` -- contributed SymmetricCipher interface.
- `code:key_deviration_function.go` -- contributed KeyDerivationFunction interface.
- `code:hmac_utils.go` -- contributed HMAC utilities.
