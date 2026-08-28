---
title: Dependencies
last_reviewed: 2026-08-28
tags: [architecture, dependencies, go-modules]
folder: architecture
sources:
  - code:go.mod
  - code:go.sum
agent_routing:
  code_change_relevance: conditional
  task_intents: [architecture-change]
  applies_to_paths:
    - go.mod
    - go.sum
  applies_to_symbols: []
---

# Dependencies

## Runtime dependencies

The library has **zero external runtime dependencies**. All core cryptographic operations use Go standard library packages:

- `crypto/aes` -- AES block cipher
- `crypto/cipher` -- CBC and GCM modes
- `crypto/elliptic` -- Elliptic curve operations (P256, P384, P521)
- `crypto/rand` -- Cryptographic random number generation
- `crypto/hmac` -- HMAC for message authentication
- `crypto/sha1`, `crypto/sha256`, `crypto/sha512` -- Hash functions for KDF
- `encoding/hex` -- Hex encoding/decoding
- `encoding/binary` -- Integer serialization
- `math/big` -- Big integer arithmetic
- `hash` -- Hash interface
- `io` -- I/O operations

## Test dependencies

- `github.com/stretchr/testify` v1.8.1 -- Test assertions (and its indirect dependencies: `github.com/davecgh/go-spew`, `github.com/kr/pretty`, `github.com/pmezard/go-difflib`, `gopkg.in/check.v1`, `gopkg.in/yaml.v3`)

## Source References

- `code:go.mod` -- contributed module and dependency declarations.
- `code:go.sum` -- contributed dependency checksums.
