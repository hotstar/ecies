---
title: Customer context
last_reviewed: 2026-08-28
tags: [readiness-placeholder, customer-context, domains]
folder: domains
sources:
  - repo-doc:README.md
agent_routing:
  code_change_relevance: skip
  task_intents: []
  applies_to_paths: []
  applies_to_symbols: []
---

# Customer context

> Readiness page: generated as a human-owned customer-context placeholder and still needs human review.

This is an open-source Go library for ECIES encryption. The "customers" are developers who use this library for encrypting and decrypting data using elliptic curve cryptography.

## Agent-critical customer context

The library is used by developers who need ECIES encryption compatible with Botan (C++) and Bouncy Castle (Java) implementations.

## Customer journeys

1. A developer imports the library in a Go project
2. They generate a key pair using `GenerateKey()`
3. They encrypt data using `ecies.Encrypt(publicKey, plaintext)`
4. They decrypt data using `ecies.Decrypt(privateKey, ciphertext)`

## Source References

- `repo-doc:README.md` -- contributed usage context and compatibility information.

## Suggested Content

- Add developer stories or use cases if known.
- Add specific integration partners or consumers if applicable.
