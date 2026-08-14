# Architecture

Vaultlet has three intentionally narrow layers.

The public Python facade validates backend and time configuration and exposes
`MasterKey`, `FileBackend`, `RedisBackend`, `Vaultlet`, and tenant-scoped
`TenantStore` handles.
Identifiers, buffers, batch shapes, and JSON values cross the extension boundary once
per public operation and are validated in Rust. Native implementation details remain
private in `vaultlet._vaultlet`.

The Rust service owns the security boundary. It derives opaque record identifiers,
encrypts values before persistence, authenticates values after reads, applies TTL
semantics, coordinates lifecycle, and maps stable error categories to Python.
Database operations, encryption, decryption, and complete JSON validation run outside
Python's event-loop thread. Copying caller-owned buffers, encoding Python JSON input,
normalizing batch arguments, and materializing returned Python objects happen
synchronously at the extension boundary and are bounded by the documented value and
batch limits.

`Vaultlet.tenant()` creates a native tenant handle. The handle validates the tenant
identifier once and retains its blinded tenant token and zeroizing AEAD context.
Singular and batch byte and JSON operations reuse that context, and bulk Python
results are constructed during one final interpreter attachment. JSON reads validate
MessagePack and build a compact structural index off the event-loop thread. Returned
objects and arrays are immutable native views that share the zeroizing decrypted
buffer and materialize nested views or Python scalars on access.

Key enumeration takes a caller limit capped by the package maximum and an optional
versioned cursor bound to the originating store and tenant. Each backend resumes
after the cursor's opaque record identifier and retains one encrypted lookahead row.
Only the bounded result is passed to the service for authentication and decryption;
the last scanned identifier becomes the next cursor when another row exists.

The internal asynchronous `Backend` trait receives only blinded 32-byte record IDs,
blinded tenant tokens, and versioned encrypted envelopes. It specifies snapshot batch
and catalogue reads, atomic mutations, header replacement, ordered expiry scans,
revision-guarded deletes, lifecycle, and durability. Contract tests run against
SQLite, redb, Redis, and the test-only in-memory backend.

## Concurrency

SQLite WAL coordinates concurrent snapshot readers and one transactional writer
across processes. A small per-instance read pool permits parallel local reads; an
available reader connection is acquired asynchronously before blocking work is
scheduled, and an async writer gate prevents a burst of callers from occupying
blocking threads while SQLite waits for its cross-process write lock. redb provides
concurrent MVCC readers and one writer inside one exclusive process owner. A bulk
mutation, encrypted key catalogue, and expiry-index changes share one durable
transaction on both file engines. Expired candidates are authenticated in bounded
batches bounded by both record count and encrypted bytes, then cleaned with one
durable backend transaction per batch.

Redis uses separate multiplexed read and write connection managers. Snapshot reads
are one Redis command or one Lua script. Mutations, catalogue changes, expiry-index
changes, guarded deletes, initialization, and header rotation execute atomically in
Lua, followed on the same connection by `WAITAOF`. Scripts are addressed by SHA and
loaded on demand, including recovery after `SCRIPT FLUSH`. A SHA-256-derived hash tag
places the data hash, catalogue sorted set, and expiry sorted set in one Redis hash
slot for compatible routing proxies.

Closing prevents new operations, stops and awaits expiry maintenance, waits for
in-flight operations through a lifecycle lock, and then drops the backend. Close
before `fork`; use fresh instances in parent and child.

## Backend scope

`FileBackend` selects a native engine for one local regular file. SQLite is the
default and supports shared multi-process ownership. redb is an explicit exclusive
single-process option. `RedisBackend` selects one logical store by endpoint and stable
namespace and supports independent processes and hosts. Python-defined backends are
not accepted: calling Python inside the Rust security and persistence path would
reintroduce interpreter and trust-boundary coupling. Network filesystems are outside
both file engines' contract.
