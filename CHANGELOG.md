# Changelog

All notable changes to Vaultlet are documented in this file.

## 0.1.0 - Unreleased

### Added

- Async tenant-scoped byte and strict JSON key-value operations, including atomic
  batches, metadata, TTL, explicit cleanup, and lifecycle management.
- A private Rust/PyO3 core using HKDF-SHA-256, HMAC-blinded identifiers,
  XChaCha20-Poly1305 envelopes, and crash-safe durable transactions.
- Stable typed errors for invalid keys, integrity failures, locking, backend failure,
  closed stores, serialization, configuration, and value-kind mismatches.
- Native stable-ABI packaging for CPython 3.12-3.14, cross-platform release automation,
  security and storage documentation, examples, and reproducible benchmark workloads.
- Selectable SQLite/WAL shared-process and redb exclusive-process file engines with
  the same encrypted data contract.
- Shared Redis 7.2+ storage with atomic Lua mutations, multiplexed connections,
  optional ACL credentials, public-root TLS through `rediss://`, and acknowledged AOF
  durability.
- Tenant-scoped encrypted key enumeration, transactionally coupled to value and
  expiry mutations.
- Atomic master-key rotation through a wrapped internal data key and crash-safe
  recovery of provably empty interrupted initialization files.
- Musllinux x86-64 and arm64 wheels with Alpine installation smoke tests.
- Native tenant handles that retain zeroizing tenant crypto contexts across byte,
  JSON, metadata, enumeration, and batch operations.
- Production-path Criterion workloads and an installed-release-wheel benchmark
  matrix covering latency distributions, throughput, concurrency, expiry cleanup,
  event-loop responsiveness, peak RSS, and Python allocations.
- Bounded tenant key enumeration with store-and-tenant-bound continuation cursors,
  caller limits, and one encrypted lookahead row per page.
- Explicit item-count and aggregate-value limits for batch operations.
- A private vulnerability-reporting policy and an exact-commit release gate using
  locked validation dependencies and cache-free release builds.
