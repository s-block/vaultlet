# Security

Report suspected vulnerabilities privately as described in the repository
[security policy](../SECURITY.md).

## Security properties

Vaultlet protects persisted values and logical identifiers against an attacker who
can read or modify the persisted backend state but does not possess the 256-bit
master key. Each new store has a random store ID, data key, data salt, and wrapping salt.
HKDF-SHA-256 derives independent wrapping, lookup, and tenant-root keys.
HMAC-SHA-256 blinds tenant and key identifiers. A separate tenant key encrypts every
record and catalogue name with XChaCha20-Poly1305 and a fresh 192-bit nonce.
Continuation cursors contain an opaque record position and a tenant-scoped HMAC tag;
altered cursors or cursors from another store or tenant are rejected.

Authenticated data binds the format version, store ID, opaque record ID, value kind,
expiry, plaintext size, tenant token, and random revision. Modified envelopes,
metadata, or record swaps fail with `IntegrityError`; a different master key fails
with `InvalidKeyError`. Unknown newer Vaultlet formats fail closed. The expiry index
is only a scheduling hint: cleanup authenticates the corresponding record and uses
revision-guarded deletion.

New files use user-only `0600` permissions on Unix. On Windows, file access follows
the containing directory's inherited ACL; applications should use a directory whose
ACL permits only the service identity and administrators. Backups require the same
controls as the live file.

Redis transport, authentication, authorization, availability, and operational
durability remain deployment responsibilities. Use `rediss://` across untrusted
networks. TLS server certificates must chain to the bundled public Web PKI roots.
Supply Redis username and password separately from the endpoint, grant access only to
the selected Vaultlet namespace, and permit the required hash, sorted-set, scripting,
and `WAITAOF` commands. Redis credentials necessarily remain in live client memory so
the connection manager can reconnect; protect the process and its configuration.

## Key custody

Vaultlet never stores the application master key. It stores a randomly generated
internal data key only as authenticated ciphertext wrapped by the master key. Generate
a master key with `MasterKey.generate()`, export it deliberately, and keep it in a
secret manager or equivalent protected configuration. Losing it makes the data
unrecoverable. Anyone who obtains both the persisted backend state and master key can
decrypt values. Vaultlet does not derive keys from passwords.

`rotate_master_key()` atomically replaces the wrapped header without re-encrypting
records or changing blinded identifiers. Existing open instances retain the same
internal data key and continue operating; new instances require the replacement key.
Only an instance whose observed header is still current may rotate it, preventing
competing processes from silently overwriting a newer rotation.

Rust-owned key buffers and temporary plaintext are zeroized where their ownership
allows it. Python `bytes`, strings, JSON objects, interpreter memory, swap, core dumps,
and allocator copies cannot be reliably zeroized. At-rest encryption does not protect
against a compromised live process, debugger, malicious extension, or caller already
authorized to export the key.

## Metadata and integrity limits

The backend reveals approximate database size, record count, tenant grouping through
blinded tokens, ciphertext sizes, expiry-index timestamps, access patterns, and update
timing. Redis additionally reveals a deterministic SHA-256 digest of the configured
namespace. Raw tenant IDs, key names, and values remain encrypted or blinded.

Authenticated encryption detects modification and relocation of records. Without an
external trusted monotonic value, it cannot prove that the entire database was not
deleted or rolled back to an older, internally valid snapshot. Secure deletion is
also outside the storage guarantee because filesystems, AOF history, backups, and
storage devices may retain old data.

TTL uses the system wall clock. Clock movement can make records expire earlier or
later; every read uses the current clock and never returns a record it currently sees
as expired.

## Operation

SQLite WAL stores support independent processes on one local filesystem. SQLite
serializes write transactions while readers observe snapshots. redb files are
exclusively owned by one process and one open `Vaultlet` instance. Network filesystems
are unsupported because their locking and durability behavior does not satisfy this
contract. Redis 7.2 or newer supports independent clients and must have AOF enabled;
Vaultlet confirms local AOF persistence for each acknowledged mutation but does not
configure replication, failover, backups, eviction, or server persistence policy.
Configure the Vaultlet keyspace as non-evictable and monitor AOF health. Close before
`fork` and open separate instances in parent and child.

Database and cryptographic work runs off the Python event loop. Argument copying,
Python JSON encoding, batch normalization, and returned-object materialization remain
synchronous and are bounded by the documented value and batch limits. Tokio cannot
cancel blocking work after it starts, so cancellation of a write awaitable means the
transaction is either fully absent or fully committed; callers may receive
`CancelledError` before learning which outcome occurred. Use an application-level
idempotency or read-after-cancellation strategy where acknowledgement is important.
Redis connection loss or a response timeout can likewise occur after an atomic script
has committed; use the same read-after-error strategy for mutation acknowledgement.

Tenant handles are a namespacing safety boundary, not authentication or authorization.
Authenticate each caller and map it to a trusted tenant identifier before selecting a
handle. Use a stable application-defined identifier rather than a bearer token, API
key, session ID, or other credential that rotates. Never accept an arbitrary tenant ID
as proof of access.
