---
title: How to set up the library
last_reviewed: 2026-08-28
tags: [readiness-placeholder, service-setup, engineering]
folder: engineering
sources:
  - repo-doc:README.md
agent_routing:
  code_change_relevance: conditional
  task_intents: [repo-onboarding]
  applies_to_paths: []
  applies_to_symbols: []
---

# How to set up the library

> Readiness page: generated from repo evidence for `service-setup` and still needs human review.

## Prerequisites

- Go 1.18 or later
- The library is a standard Go module: `github.com/hotstar/ecies`

## Installation

```bash
go get github.com/hotstar/ecies
```

## Usage

Import the package and use `NewECIES()` for the default implementation:

```go
import "github.com/hotstar/ecies"

ecies := NewECIES()
encrypted, err := ecies.Encrypt(publicKey, plaintext)
decrypted, err := ecies.Decrypt(privateKey, encrypted)
```

For a customized implementation, use `NewCustomizedECIES()` with your own components.

## Source References

- `repo-doc:README.md` -- contributed installation and usage examples.

## Suggested Content

- Confirm Go version compatibility for Go 1.18+.
- Add any missing local reset steps or failure scenarios.
