# Vaultlet

Vaultlet is an async, encrypted, multi-tenant persistent key-value store for Python,
powered by Rust. It is designed for credentials, sessions, agent state, checkpoints,
cached data, and other sensitive application data.

The Rust core performs key derivation, authenticated encryption, expiry enforcement,
key enumeration, and durable backend transactions without handing plaintext to the
storage engine. Tenant-scoped handles make isolation part of every data operation.
Values can be opaque bytes or an explicit JSON-compatible subset; no pickle or Python
object deserialization is used.

## Requirements

- CPython 3.12, 3.13, or 3.14
- A supported manylinux, musllinux, macOS, or Windows native wheel
- Redis 7.2 or newer with AOF enabled when using `RedisBackend`

Vaultlet uses the CPython 3.12 stable ABI. Standard GIL-enabled CPython builds are
supported; free-threaded CPython builds require a separately compiled artifact.

## Installation

```bash
pip install vaultlet
```

## Quick start

```python
import asyncio
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

import vaultlet


async def main() -> None:
    # This walkthrough is intentionally disposable. Persistent stores must restore
    # the same key from a secret manager on every open.
    with TemporaryDirectory(prefix="vaultlet-quickstart-") as directory:
        key = vaultlet.MasterKey.generate()
        async with await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(Path(directory) / "state.vaultlet"),
            key=key,
        ) as store:
            tenant = store.tenant("customer-123")
            await tenant.set("token", b"secret", ttl=timedelta(hours=1))
            await tenant.set_json("checkpoint", {"step": 4, "messages": []})
            checkpoint = await tenant.get_json("checkpoint")
            if checkpoint is None:
                raise RuntimeError("checkpoint did not round-trip")

            stored_keys: list[str] = []
            cursor = None
            while True:
                listing = await tenant.keys(limit=100, cursor=cursor)
                stored_keys.extend(listing.keys)
                if listing.next_cursor is None:
                    break
                cursor = listing.next_cursor
            if set(stored_keys) != {"checkpoint", "token"}:
                raise RuntimeError("key listing was incomplete")


asyncio.run(main())
```

The master key is never stored in the Vaultlet backend. `export_bytes()` and
`export_base64()` are deliberately explicit because the application owns key
provisioning, backup, and access control. For a persistent store, generate and save
the key once, then obtain it from protected configuration and restore it with
`MasterKey.from_bytes(...)` or `MasterKey.from_base64(...)`. Losing the key makes the
store unrecoverable.

`FileBackend` defaults to SQLite in WAL mode, which supports independent processes
opening and coordinating through the same local store. Select redb explicitly for
exclusive single-process ownership:

```python
backend = vaultlet.FileBackend(
    Path("state.vaultlet"),
    engine=vaultlet.StorageEngine.REDB,
)
```

SQLite and redb files use different container formats. Reopen a file with the engine
that created it. SQLite is the required file engine for multi-process deployments;
redb returns `StoreLockedError` when another owner has the file open.

For a shared network backend, configure one stable Redis namespace and keep
credentials outside the endpoint:

```python
import os

backend = vaultlet.RedisBackend(
    os.environ["VAULTLET_REDIS_ENDPOINT"],  # redis:// or rediss://
    namespace="orders-production",
    username=os.environ.get("VAULTLET_REDIS_USERNAME"),
    password=os.environ.get("VAULTLET_REDIS_PASSWORD"),
)
```

`rediss://` validates the server certificate against bundled public Web PKI roots;
standard managed Redis certificates need no CA, client-certificate, or client-key
arguments. The endpoint must not contain credentials, so exceptions and object
representations cannot accidentally expose them. The selected Redis database is read
from the endpoint path, such as `/2`.

Redis AOF is required because every mutation is followed by `WAITAOF` before Vaultlet
acknowledges it. The Redis ACL must permit the namespace's keys plus the hash,
sorted-set, scripting, and `WAITAOF` commands used by Vaultlet. Each namespace maps to
three Redis keys in one hash slot; use a unique, stable namespace for each logical
store and never point unrelated master keys at the same namespace. Connect through a
standalone Redis endpoint or a compatible routing proxy.

## Bytes, JSON, and atomic batches

Bytes are the primitive API. Values may be any C-contiguous Python buffer and reads
return immutable `bytes`:

```python
tenant = store.tenant("customer-123")
await tenant.set_many({"access": b"a", "refresh": bytearray(b"b")})
tokens = await tenant.get_many(["refresh", "access", "missing"])
```

JSON methods accept `None`, booleans, finite 64-bit numbers, strings, lists, and
string-keyed dictionaries. They reject cycles, non-finite floats, oversized
integers, arbitrary objects, and pickle. JSON objects and arrays are returned as
immutable `JsonObject` and `JsonArray` views backed by the authenticated MessagePack
buffer. The complete structure is validated off the event-loop thread, while nested
views and Python scalar objects are created only when accessed:

```python
await tenant.set_many_json(
    {
        "checkpoint": {"step": 5, "messages": []},
        "pending-writes": [],
    }
)

checkpoint = await tenant.get_json("checkpoint")
if isinstance(checkpoint, vaultlet.JsonObject):
    step = checkpoint["step"]
    mutable_checkpoint = checkpoint.to_builtin()
```

The decrypted buffer is zeroized after its final related view is released. Passing a
returned view back to `set_json` or `set_many_json` copies its already validated
MessagePack directly without traversing a Python container graph.

Each `set_many`, `set_many_json`, or `delete_many` call is one durable atomic
transaction. Each bulk read observes one database snapshot and preserves input
order in its returned dictionary; JSON values inside `get_many_json` results remain
immutable views. Reading JSON as bytes, or bytes as JSON, raises
`TypeMismatchError`. Batch calls accept at most `MAX_BATCH_ITEMS` items, and the
aggregate encoded values in a write batch may not exceed
`MAX_BATCH_VALUE_BYTES` (64 MiB). Split larger workloads into multiple operations.

`await tenant.keys(limit=..., cursor=...)` returns one `KeyListing` page containing
at most that many live keys for exactly one tenant, sorted lexically within that
page. The default limit is 1,000 and `MAX_KEY_LIST_LIMIT` is 10,000. When
`next_cursor` is present, pass it unchanged to the next call; `has_more` remains as a
convenience indicator. Cursors are opaque, versioned, and bound to the originating
store and tenant. Each page observes its own database snapshot, so concurrent
catalogue changes can affect a multi-page traversal.

The backend reads at most one encrypted lookahead row beyond the limit and decrypts
at most the requested number. Expired entries in the bounded slice are omitted and
cleaned, so a page can contain fewer keys than its limit while a continuation cursor
is present. Catalogue changes and value mutations share one transaction, including
when SQLite writers run in separate processes or Redis clients run on separate hosts.

## Expiry and lifecycle

`ttl` accepts finite non-negative seconds or `datetime.timedelta`. `expires_at`
accepts a timezone-aware `datetime`; the options are mutually exclusive. Expired
records are immediately absent from reads. Lazy deletion, a bounded background
worker, and `await store.purge_expired()` remove their encrypted storage.

Open stores should always be closed with `async with` or `await store.aclose()`.
SQLite and Redis stores may have multiple owners; redb stores have one exclusive
owner. A cancelled mutating awaitable is still atomic: cancellation can be observed
by Python even though the whole transaction subsequently commits.

## Security and operation

Vaultlet blinds tenant and key identifiers and encrypts each value with a distinct
XChaCha20-Poly1305 nonce and a tenant-derived key. Authenticated metadata binds the
store identity, record identity, encoding, expiry, and revision. The redb backend
uses immediate two-phase commits; SQLite uses WAL with full synchronization. Both
create new database files with mode `0600` on Unix. Windows files use the directory's
inherited ACL.

The Redis backend uses atomic Lua scripts and confirms local AOF persistence with
`WAITAOF`. Use `rediss://` whenever traffic can cross an untrusted network, and apply
normal Redis access controls, network isolation, persistence monitoring, and backup
policy.

Choose stable, application-defined tenant IDs such as internal account UUIDs. Bearer
tokens, API keys, session IDs, and other rotating credentials belong in the
authentication layer; using one as a tenant ID would select a different encrypted
namespace when that credential changes.

`await store.rotate_master_key(replacement)` atomically rewraps the stable internal
data key. Existing open processes continue using the same data schedule, while future
opens must use the replacement master key.

Tenant handles prevent accidental cross-tenant access; they do not authenticate
callers. Applications must map authenticated callers to trusted tenant IDs.
Network filesystems are not supported for file backends. See
[Security](docs/Security.md), [Architecture](docs/Architecture.md), and
[Storage Format](docs/StorageFormat.md) for the complete operational contract.

## Development and benchmarks

See [Development](docs/Development.md) for the toolchain and validation commands.
[Benchmarks](docs/Benchmarks.md) documents reproducible workloads and how to report
results without treating unencrypted stores as security-equivalent comparisons.

## License

Vaultlet is available under the [MIT License](LICENSE).
