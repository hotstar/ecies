---
title: Repository Overview
last_reviewed: 2026-08-28
tags: [ecies, overview, encryption, elliptic-curve]
folder: overview
sources:
  - code:ecies.go
  - code:README.md
agent_routing:
  code_change_relevance: conditional
  task_intents: [repo-onboarding]
  applies_to_paths: []
  applies_to_symbols: []
---

# Repository Overview

## Purpose

This repository provides a Golang implementation of the Elliptic Curve Integrated Encryption Scheme (ECIES), following the Shoup's version specification (ISO 18033-2 / IEEE Std 1363a). It is designed to be compatible with the C++ Botan and Java Bouncy Castle ECIES implementations, enabling cross-language encrypted data exchange.

## Top-level layout

The entire library is a single Go package `ecies` at the repo root, with no subpackages. Source files implement:

- **`ecies.go`** -- Core ECIES struct, `Encrypt()` and `Decrypt()` methods, `NewECIES()` and `NewCustomizedECIES()` constructors
- **`key_pair.go`** -- `PublicKey`, `PrivateKey` types; `GenerateKey()`, serialize/deserialize functions
- **`curve.go`** -- Default curve (secp256r1/P256), `SetCurve()`, `GetCurve()`, `GetECPointByteLength()`
- **`ecsvdp_dh_key_agreement.go`** -- ECSVDP-DH key agreement implementation (IEEE P1363 7.2.1)
- **`key_agreement.go`** -- `KeyAgreement` interface
- **`kdf_utils.go`** -- KDF1/KDF2 key derivation implementation (ISO 18033)
- **`key_deviration_function.go`** -- `KeyDerivationFunction` interface
- **`key_deviration_function_1.go`** -- KDF1 wrapper
- **`key_deviration_function_2.go`** -- KDF2 wrapper
- **`symmetric_cipher.go`** -- `SymmetricCipher` interface
- **`aes_cbc_pkcs7_cipher.go`** -- AES-CBC with PKCS7 padding cipher
- **`aes_gcm_cipher.go`** -- AES-GCM cipher
- **`pkcs7_utils.go`** -- PKCS7 padding utilities (constant-time)
- **`hmac_utils.go`** -- HMAC utilities (SHA256)
- **`encode_utils.go`** -- Hex encode/decode utilities
- **`example.go`** -- Usage example demonstrating key generation, encryption, decryption

## Who built it

Developed by the Disney+Hotstar Security Team and contributed to the open-source community.

## Source References

- `code:ecies.go` -- contributed ECIES struct and main methods.
- `code:README.md` -- contributed project purpose and background.
