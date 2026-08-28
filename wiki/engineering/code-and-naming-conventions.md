---
title: Code and naming conventions
last_reviewed: 2026-08-28
tags: [readiness-placeholder, code-and-naming-conventions, engineering]
folder: engineering
sources:
  - code:ecies.go
  - code:curve.go
  - code:key_pair.go
agent_routing:
  code_change_relevance: conditional
  task_intents: [repo-onboarding]
  applies_to_paths:
    - "*.go"
  applies_to_symbols: []
---

# Code and naming conventions

> Readiness page: generated from repo evidence for `code-and-naming-conventions` and still needs human review.

## Package structure

Single package `ecies` at the repo root containing all source files. No subpackages.

## Naming conventions

- Types use PascalCase: `ECIES`, `PublicKey`, `PrivateKey`, `KeyAgreement`, `KeyDerivationFunction`, `SymmetricCipher`
- Methods use PascalCase for exported: `NewECIES()`, `Encrypt()`, `Decrypt()`, `GenerateKey()`
- Un-exported types and functions use camelCase: `kdf`, `i2osp`, `zeroPad`
- Error variables use camelCase with `err` prefix: `errInvalidLengthParameter`, `errPKCS7Padding`
- Interfaces use PascalCase: `KeyAgreement`, `KeyDerivationFunction`, `SymmetricCipher`

## Source References

- `code:ecies.go` -- contributed ECIES struct and main methods.
- `code:curve.go` -- contributed curve configuration.
- `code:key_pair.go` -- contributed key types.

## Suggested Content

- Add Go-specific style guidelines and review expectations.
