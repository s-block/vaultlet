# Vaultlet — async encrypted key-value storage for Python

[![PyPI](https://img.shields.io/pypi/v/vaultlet)](https://pypi.org/project/vaultlet/)
[![Python](https://img.shields.io/pypi/pyversions/vaultlet)](https://pypi.org/project/vaultlet/)
[![CI](https://github.com/s-block/vaultlet/actions/workflows/ci.yml/badge.svg)](https://github.com/s-block/vaultlet/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/s-block/vaultlet/blob/main/LICENSE)

Vaultlet is a high-performance, fully async, encrypted, multi-tenant key-value store
for Python. Its Rust core, exposed through PyO3, keeps cryptography, expiry, and
durable backend work off the event loop while the Python API stays small and typed.
Use it for credentials, sessions, agent state, checkpoints, cached data, and other
sensitive application state.

- **Strong tenant isolation:** every operation uses a tenant-scoped handle, and
  tenant and key identifiers are blinded before they reach storage.
- **Async bytes and typed JSON:** store opaque buffers or safe structured state
  without pickle or arbitrary object deserialization.
- **Application-state primitives:** apply TTLs, enumerate live keys, rotate the
  master key, and commit batch reads or writes atomically.
- **SQLite, redb, and Redis:** choose shared local storage, an exclusive embedded
  store, or a durable multi-host backend without changing the tenant API.

```bash
pip install vaultlet
```

[PyPI](https://pypi.org/project/vaultlet/) · [Quick start](#quick-start) ·
[Examples](#examples) ·
[Security](https://github.com/s-block/vaultlet/blob/main/docs/Security.md) ·
[Architecture](https://github.com/s-block/vaultlet/blob/main/docs/Architecture.md) ·
[Benchmarks](https://github.com/s-block/vaultlet/blob/main/docs/Benchmarks.md) ·
[Changelog](https://github.com/s-block/vaultlet/blob/main/CHANGELOG.md)

> **Used in the real world:**
> [browser-use-mcp](https://github.com/s-block/browser-use-mcp) uses Vaultlet for
> encrypted multi-tenant state and browser-profile metadata in a real-world MCP
> server.

## Quick start

```python
import asyncio
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

import vaultlet


async def main() -> None:
    with TemporaryDirectory(prefix="vaultlet-quickstart-") as directory:
        key = vaultlet.MasterKey.generate()
        async with await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(Path(directory) / "state.vaultlet"), key=key
        ) as store:
            user = store.tenant("user-123")
            await user.set("access-token", b"secret", ttl=timedelta(hours=1))
            print(await user.get("access-token"))


asyncio.run(main())
```

The quick start is intentionally disposable. The master key is never stored in the
Vaultlet backend: for a persistent store, generate and save it once in protected
configuration, then restore it with `MasterKey.from_bytes(...)` or
`MasterKey.from_base64(...)`. Losing the key makes the store unrecoverable.

## Examples

| Goal | Entry point |
| --- | --- |
| Basic encrypted local storage | [Quick start](#quick-start) |
| Credential storage with TTL | [credentials_ttl.py](https://github.com/s-block/vaultlet/blob/main/examples/credentials_ttl.py) |
| Tenant isolation | [multi_tenant.py](https://github.com/s-block/vaultlet/blob/main/examples/multi_tenant.py) |
| Atomic JSON agent checkpoints | [agent_checkpoint.py](https://github.com/s-block/vaultlet/blob/main/examples/agent_checkpoint.py) |
| Shared Redis storage | [redis_backend.py](https://github.com/s-block/vaultlet/blob/main/examples/redis_backend.py) |

The Redis example reads its endpoint and persistent master key from
`VAULTLET_REDIS_ENDPOINT` and `VAULTLET_MASTER_KEY`; optional namespace and ACL
credentials use the `VAULTLET_REDIS_*` variables shown in the example.

## Backends

| Backend | Best fit | Ownership and durability |
| --- | --- | --- |
| SQLite (default) | Local application state shared by processes | WAL mode with full synchronization |
| redb | Embedded state owned by one process | Exclusive file ownership and immediate two-phase commits |
| Redis | State shared by processes or hosts | Atomic scripts and acknowledged AOF persistence |

## Requirements

- CPython 3.12, 3.13, or 3.14
- A supported manylinux, musllinux, macOS, or Windows native wheel
- Redis 7.2 or newer with AOF enabled when using `RedisBackend`

Vaultlet uses the CPython 3.12 stable ABI. Standard GIL-enabled CPython builds are
supported; free-threaded CPython builds require a separately compiled artifact.

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

The Rust core performs key derivation, authenticated encryption, expiry enforcement,
key enumeration, and durable backend transactions without handing plaintext to the
storage engine.

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
[Security](https://github.com/s-block/vaultlet/blob/main/docs/Security.md),
[Architecture](https://github.com/s-block/vaultlet/blob/main/docs/Architecture.md),
and [Storage Format](https://github.com/s-block/vaultlet/blob/main/docs/StorageFormat.md)
for the complete operational contract.

## Benchmarks

Vaultlet includes reproducible Rust microbenchmarks and Python end-to-end workloads
covering SQLite and redb, bytes and JSON, single and batch operations, TTL cleanup,
tenant contention, and concurrent tasks. A labelled comparison runner also includes
Redis, an encrypted `aiosqlite` baseline, and an explicitly non-equivalent DiskCache
context. See
[Benchmarks](https://github.com/s-block/vaultlet/blob/main/docs/Benchmarks.md) for the
workloads, commands, and reporting rules. Reproducible result artifacts exist for
development comparisons, but Vaultlet does not publish headline numbers until a
reportable backend and baseline run is available.

## Contributing

Contributions are welcome across benchmarks, platform support, integrations,
documentation, and security review. See
[Contributing](https://github.com/s-block/vaultlet/blob/main/CONTRIBUTING.md) for the
local workflow and the [open issues](https://github.com/s-block/vaultlet/issues) for
current roadmap work.
[Development](https://github.com/s-block/vaultlet/blob/main/docs/Development.md)
documents the complete toolchain and validation commands. Suspected vulnerabilities
belong in [private security reports](https://github.com/s-block/vaultlet/security/advisories/new),
not public issues.

## License

Vaultlet is available under the
[MIT License](https://github.com/s-block/vaultlet/blob/main/LICENSE).
