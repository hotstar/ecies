---
title: Production context
last_reviewed: 2026-08-28
tags: [readiness-placeholder, production-context, operations]
folder: operations
sources: []
agent_routing:
  code_change_relevance: skip
  task_intents: []
  applies_to_paths: []
  applies_to_symbols: []
---

# Production context

> Readiness page: generated as a human-owned production-context placeholder and still needs human review.

This is a Go library package, not a deployed service. Production context is not directly applicable. The library is consumed by other services that handle their own production concerns.

## Agent-critical constraints

N/A - this is a library package.

## Production service identity

N/A - this is a library package.

## Hot paths and performance budgets

The library includes benchmarks for encryption/decryption performance on P256, P384, and P521 curves. See benchmark tables in README.md and `benchmark_test.go`.

## Suggested Content

- This topic is not applicable to a library repository; consider disabling in readiness-config.yaml.
