# Wiki Map

## Understand the system

- [Repository Overview](overview/repo-overview.md) -- What this ECIES Go library is, its purpose, and its top-level structure.
- [Module Structure](architecture/module-structure.md) -- Component architecture, data flow, and how the ECIES pieces fit together.
- [Domain Concepts](domains/domain-concepts.md) -- Glossary of cryptographic terms and ubiquitous language used throughout the codebase.
- [Dependencies](architecture/dependencies.md) -- Zero external runtime dependencies; all crypto from Go standard library.
- [Data Models](data/data-models.md) -- Key data structures (PublicKey, PrivateKey) and ciphertext layout.

## Change behavior

- [Public API](api/public-api.md) -- Complete public surface: types, interfaces, constructors, and utility functions.
- [Configuration](engineering/configuration.md) -- How to customize the curve, KDF, symmetric cipher, and other ECIES components.
- [Code and Naming Conventions](engineering/code-and-naming-conventions.md) -- Package structure, naming patterns, and code organization.
- [Edge Cases](domains/external-edge-cases.md) -- Known error conditions and compatibility constraints.
- [Known Tradeoffs](decisions/known-tradeoffs-and-rejected-alternatives.md) -- Performance tradeoffs, curve comparisons, and architecture decisions.

## Operate in production

- [Build, Test, and Deploy](engineering/build-test-deploy.md) -- Build and test commands for this library.
- [How to run tests](engineering/how-to-run-tests.md) -- Complete test commands and test file listing.

## Onboard a new engineer

- [Repository Overview](overview/repo-overview.md) -- Start here to understand the project.
- [How to set up the library](engineering/how-to-set-up-the-library.md) -- Installation and basic usage walkthrough.
- [Public API](api/public-api.md) -- Reference for all exported functionality.
- [Code and Naming Conventions](engineering/code-and-naming-conventions.md) -- Conventions to follow when contributing.
- [Domain Concepts](domains/domain-concepts.md) -- Understanding the cryptographic terminology.
- [Customer Context](domains/customer-context.md) -- Developer-consumer context and usage journeys.
