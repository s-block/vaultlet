# Benchmarks

Vaultlet keeps benchmarks outside normal unit tests and applies no brittle performance
threshold in CI. The CI smoke only checks that benchmark workloads remain correct.

## Rust microbenchmarks

Criterion calls production tenant-context, envelope, in-place AEAD, service,
catalogue, SQLite, and redb code. It measures encryption/decryption, borrowed envelope
inspection, authenticated reads, durable writes, and durable batches. Value-oriented
groups cover 64-byte, 4-KiB, 1-MiB, and 10-MiB inputs; batch groups cover 1, 10, 100,
and 1,000 entries. A production JSON group isolates validation and structural-index
construction for flat objects with 1,000 and 20,000 fields:

```bash
cargo bench --manifest-path rust/Cargo.toml --bench core
```

Run on an otherwise idle machine. Retain Criterion's raw output together with CPU,
memory, OS, filesystem, Rust version, and power-management configuration. The
benchmark adapter contains no substitute crypto or storage implementation.

## Python end-to-end workloads

Build a release wheel, install it into an isolated environment, and invoke the matrix
with that environment's Python. The runner rejects editable/development installs:

```bash
uv run maturin build --release --out dist
python3 -m venv .benchmark-venv
.benchmark-venv/bin/pip install dist/*.whl
.benchmark-venv/bin/python benchmarks/release_matrix.py \
  --report --output benchmarks/results/release.json
```

The report matrix separates bytes and JSON across 64 B, 4 KiB, 1 MiB, and 10 MiB;
singular and batch sizes 1, 10, 100, and 1,000; 1, 8, and 32 tasks; one-tenant and
many-tenant contention; and SQLite and redb without taking a full Cartesian product.
Omit `--report` to run the full matrix; cases whose simultaneous logical payload would
exceed 256 MiB are skipped. Every isolated case records warm hits, misses, sets, gets,
deletes, metadata, existence checks, key enumeration, lazy TTL cleanup, and explicit
purge, with latency distributions, throughput, peak RSS, and Python allocation
observations. Use `--quick` for a non-reportable development sample.
The report and target sets also include a node-heavy JSON object because immutable
view indexing and Python reconstruction costs scale with structural nodes rather
than encoded bytes alone. JSON responsiveness records both write traversal and read
parsing/indexing. A separate full-materialization phase measures the explicit
conversion from immutable views to built-in Python containers and its event-loop gap.

The labelled comparison workloads remain available separately:

```bash
uv sync --group benchmark
uv run --group benchmark pyperf command --name vaultlet-sqlite-bytes -- \
  python benchmarks/compare.py vaultlet-sqlite bytes --size 4096 --tasks 8
uv run --group benchmark pyperf command --name vaultlet-redb-bytes -- \
  python benchmarks/compare.py vaultlet-redb bytes --size 4096 --tasks 8
VAULTLET_TEST_REDIS_ENDPOINT=redis://127.0.0.1:6379/0 \
uv run --group benchmark pyperf command --name vaultlet-redis-bytes -- \
  python benchmarks/compare.py vaultlet-redis bytes --size 4096 --tasks 8
uv run --group benchmark pyperf command --name aiosqlite-aead-bytes -- \
  python benchmarks/compare.py aiosqlite-aead bytes --size 4096 --tasks 8
uv run --group benchmark pyperf command --name diskcache-bytes -- \
  python benchmarks/compare.py diskcache bytes --size 4096 --tasks 8
uv run --group benchmark pyperf command --name vaultlet-sqlite-agent-json -- \
  python benchmarks/compare.py vaultlet-sqlite json --tasks 8
uv run python benchmarks/smoke.py
```

Criterion separates crypto, envelope parsing, and durable backend work. The release
matrix captures Python-to-Rust conversion, JSON serialization, asynchronous service
work, and final Python reconstruction at the public boundary. Retain both raw result
sets and their environment metadata for before/after comparisons. Do not publish
performance claims until those artifacts exist.

The Redis workload requires a disposable Redis 7.2 or newer server with AOF enabled.
Record Redis version, topology, persistence policy, network path, TLS mode, and server
hardware with the results. Redis namespaces are unique per benchmark process so an
old wrapped header cannot contaminate a later sample.

The supplied encrypted Python baseline uses aiosqlite in WAL mode with
`synchronous=FULL`, HMAC-SHA-256 identifiers, AES-GCM values, and one commit per
operation. DiskCache is an explicitly labelled unencrypted local-cache context; its
result is not a security-equivalent comparison. Keep value sizes and transaction
boundaries aligned when extending either workload.
