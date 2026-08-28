---
title: Configuration
last_reviewed: 2026-08-28
tags: [engineering, configuration, env-vars, curve]
folder: engineering
sources:
  - code:curve.go
  - code:ecies.go
agent_routing:
  code_change_relevance: conditional
  task_intents: [repo-onboarding]
  applies_to_paths: []
  applies_to_symbols: [SetCurve, CURVE, GetCurve]
---

# Configuration

## Curve configuration

The library uses a global variable `curve` to determine which elliptic curve is used for all cryptographic operations. The default curve is `secp256r1` (P256).

```go
// Change the curve at runtime
ecies.SetCurve(elliptic.P384())

// Reset to default
ecies.ClearCurve()
```

## Custom ECIES configuration

The `NewCustomizedECIES()` constructor allows replacing any component:

```go
ecies.NewCustomizedECIES(
    ka,                        // KeyAgreement interface
    cipher,                    // SymmetricCipher interface
    kdf,                       // KeyDerivationFunction interface
    crypto.SHA256,             // HMAC hash algorithm
    16,                        // Encryption key byte size
    16,                        // MAC key byte size
)
```

## Default configuration

| Component | Default |
| --- | --- |
| Elliptic curve | secp256r1 (P256) |
| Key agreement | ECSVDP-DH (EcsvdpDhKeyAgreement) |
| KDF | KDF2 with SHA256 (KeyDerivationFunction2) |
| Symmetric cipher | AES-CBC-PKCS7 padding (AesCbcPkcs7Cipher) |
| MAC | HMAC-SHA256 |
| Encryption key size | 16 bytes (128-bit AES) |
| MAC key size | 16 bytes (128-bit) |

## Source References

- `code:curve.go` -- contributed curve configuration.
- `code:ecies.go` -- contributed default component configuration.
