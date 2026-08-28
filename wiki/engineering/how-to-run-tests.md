---
title: How to run tests
last_reviewed: 2026-08-28
tags: [readiness-placeholder, test-commands, engineering]
folder: engineering
sources:
  - code:ecies_test.go
  - code:benchmark_test.go
  - code:go.mod
agent_routing:
  code_change_relevance: conditional
  task_intents: [repo-onboarding]
  applies_to_paths:
    - "**_test.go"
  applies_to_symbols: []
---

# How to run tests

> Readiness page: generated from repo evidence for `test-commands` and still needs human review.

## Running tests

Standard Go test commands:

```bash
# Run all unit tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run benchmarks
go test -bench=. ./...
```

## Test files

The repo includes test files for all major components:

- `ecies_test.go` -- ECIES encryption/decryption tests
- `aes_cbc_pkcs7_cipher_test.go` -- AES-CBC cipher tests
- `aes_gcm_cipher_test.go` -- AES-GCM cipher tests
- `benchmark_test.go` -- Performance benchmarks for P256, P384, P521 curves
- `curve_test.go` -- Curve utility tests
- `example_test.go` -- Example tests
- `hmac_utils_test.go` -- HMAC utility tests
- `kdf_utils_test.go` -- KDF tests
- `key_pair_test.go` -- Key generation/serialization tests
- `encode_utils_test.go` -- Hex encode/decode tests
- `pkcs7_utils_test.go` -- PKCS7 padding tests
- `ecsvdp_dh_key_agreement_test.go` -- Key agreement tests

## Dependencies

- The library uses `github.com/stretchr/testify` for assertions (v1.8.1)

## Suggested Content

- Add common failure modes for test scenarios.
- Add test data requirements if any.
