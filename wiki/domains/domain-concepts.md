---
title: Domain Concepts
last_reviewed: 2026-08-28
tags: [domains, ecies, glossary, cryptography]
folder: domains
sources:
  - code:ecies.go
  - code:key_agreement.go
  - code:kdf_utils.go
  - code:symmetric_cipher.go
  - code:hmac_utils.go
  - code:pkcs7_utils.go
agent_routing:
  code_change_relevance: conditional
  task_intents: [domain-behavior-change]
  applies_to_paths: []
  applies_to_symbols: []
---

# Domain Concepts

## Glossary

- **ECIES** -- Elliptic Curve Integrated Encryption Scheme. A public-key encryption scheme that combines elliptic curve Diffie-Hellman (ECDH) key agreement with a symmetric cipher and a MAC.
- **ECSVDP-DH** -- Elliptic Curve Secret Value Derivation Primitive, Diffie-Hellman variant. The key agreement mechanism specified in IEEE P1363 7.2.1.
- **KDF** -- Key Derivation Function. Derives one or more cryptographic keys from a shared secret. This implementation supports KDF1 and KDF2 per ISO 18033.
- **KDF2** -- The default KDF variant. Differs from KDF1 in the counter starting value (KDF2 starts at 1, KDF1 at 0).
- **HMAC** -- Hash-based Message Authentication Code. Used to authenticate the ciphertext and detect tampering.
- **PKCS7 Padding** -- A padding scheme for block ciphers where the padding bytes all have the value equal to the number of padding bytes.
- **Shoup's version** -- An ISO-standardized variant of ECIES described in Victor Shoup's paper, as opposed to older, less standardized variants.
- **secp256r1** -- The default elliptic curve, also known as P256 or prime256v1. A NIST-standardized curve providing 128-bit security level.

## Ubiquitous language

| Term | Meaning |
| --- | --- |
| Ephemeral key pair | A temporary key pair generated for each encryption operation; never reused |
| Shared secret | The output of the ECDH key agreement, used as input to the KDF |
| Encryption key | One half of the KDF output, used by the symmetric cipher |
| MAC key | The other half of the KDF output, used for authentication |
| Ciphertext | The encrypted message including ephemeral public key, encrypted bytes, and MAC |

## Source References

- `code:ecies.go` -- contributed core ECIES structure.
- `code:key_agreement.go` -- contributed key agreement interface.
- `code:kdf_utils.go` -- contributed KDF implementation.
- `code:symmetric_cipher.go` -- contributed cipher interface.
- `code:hmac_utils.go` -- contributed HMAC utilities.
- `code:pkcs7_utils.go` -- contributed PKCS7 padding.
