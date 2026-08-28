---
title: Known tradeoffs and rejected alternatives
last_reviewed: 2026-08-28
tags: [readiness-placeholder, tradeoffs-rejected-alternatives, decisions]
folder: decisions
sources:
  - repo-doc:README.md
  - code:ecies.go
agent_routing:
  code_change_relevance: conditional
  task_intents: [domain-behavior-change]
  applies_to_paths: []
  applies_to_symbols: []
---

# Known tradeoffs and rejected alternatives

> Readiness page: generated from repo evidence for `tradeoffs-rejected-alternatives` and still needs human review.

## Known tradeoffs

- **Shoup's version vs older ECIES variants**: This implementation follows Victor Shoup's ISO 18033-2 specification, not older ECIES variants. This ensures compatibility with Botan (C++) and Bouncy Castle (Java) implementations.
- **Default curve**: The default curve is `secp256r1` (P256) chosen for broad compatibility. The library supports P384 and P521 via `SetCurve()`.
- **Default cipher**: AES-CBC-PKCS7Padding is the default symmetric cipher, with AES-GCM available as an alternative (`NewAesGcmCipher()`).
- **Performance**: P256 provides the fastest encryption/decryption. P384 is approximately 17-18x slower for encryption. P521 is approximately 54-55x slower for encryption. See benchmark tables in README.md for detailed performance comparisons.
- **RSA comparison**: RSA3072 (same security level as P256) has faster encryption but significantly slower decryption (approximately 61x slower for 128-byte messages).

## Source References

- `repo-doc:README.md` -- contributed benchmark comparisons and compatibility details.
- `code:ecies.go` -- contributed ECIES structure and method signatures.

## Suggested Content

- Add rationale for choosing this implementation approach over alternatives.
- Add ADRs or design documents if they exist.
