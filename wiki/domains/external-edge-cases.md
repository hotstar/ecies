---
title: Edge cases decided outside code
last_reviewed: 2026-08-28
tags: [readiness-placeholder, external-edge-cases, domains]
folder: domains
sources:
  - repo-doc:README.md
  - code:ecies.go
agent_routing:
  code_change_relevance: conditional
  task_intents: [domain-behavior-change]
  applies_to_paths: []
  applies_to_symbols: []
---

# Edge cases decided outside code

> Readiness page: generated from repo evidence for `external-edge-cases` and still needs human review.

## Known edge cases

- **Empty message**: The `Encrypt` method returns an error if the message is nil or empty (`"invalid length of message"`).
- **Short ciphertext**: The `Decrypt` method returns an error if the ciphertext is shorter than the public key size plus MAC size (`"invalid length of message"`).
- **Invalid MAC**: If the MAC validation fails during decryption, an error `"invalid mac data"` is returned.
- **Invalid ciphertext**: If decryption fails, an error `"invalid enc data"` is returned.
- **Invalid public key**: `DeserializePublicKey` returns an error if the point cannot be unmarshalled.

## Compatibility constraints

- Implementation follows the Shoup's version of ECIES (ISO 18033-2).
- Compatible with C++ Botan and Java Bouncy Castle implementations.
- Default curve is `secp256r1` (P256), but supports P384 and P521.
- Default components: ECDHBasicAgreement (ECSVDP-DH), KDF2 with SHA256, HMAC-SHA256, AES-CBC-PKCS7Padding.

## Source References

- `repo-doc:README.md` -- contributed compatibility and default component details.
- `code:ecies.go` -- contributed encryption/decryption edge case handling.

## Suggested Content

- Add any product or business decisions about curve selection or component choice.
