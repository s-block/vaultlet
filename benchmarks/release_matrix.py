"""Release-wheel latency, throughput, RSS, and Python-allocation matrix."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import platform
import resource
import statistics
import subprocess
import sys
import tempfile
import time
import tracemalloc
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Literal, cast

import vaultlet
from vaultlet import _vaultlet

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence

type Encoding = Literal["bytes", "json"]
type Tenancy = Literal["one", "many"]
type JsonShape = Literal["blob", "nodes"]

VALUE_SIZES = (64, 4 * 1024, 1024 * 1024, 10 * 1024 * 1024)
BATCH_SIZES = (1, 10, 100, 1_000)
TASK_COUNTS = (1, 8, 32)
MAX_CASE_BYTES = 256 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class Case:
    """One isolated benchmark-process configuration."""

    engine: str
    encoding: Encoding
    size: int
    batch: int
    tasks: int
    tenancy: Tenancy
    repetitions: int
    json_shape: JsonShape = "blob"


def percentile(values: list[int], fraction: float) -> int:
    """Return a nearest-rank percentile from non-empty integer samples."""
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * fraction)))
    return ordered[index]


def distribution(samples: list[int], logical_operations: int) -> dict[str, float | int]:
    """Summarize phase wall-time samples and logical operation throughput."""
    median = statistics.median(samples)
    return {
        "samples": len(samples),
        "min_ns": min(samples),
        "p50_ns": int(median),
        "p95_ns": percentile(samples, 0.95),
        "p99_ns": percentile(samples, 0.99),
        "max_ns": max(samples),
        "mean_ns": statistics.fmean(samples),
        "throughput_ops_s": logical_operations / (median / 1_000_000_000),
    }


async def measure(
    operation: Callable[[], Awaitable[None]], repetitions: int
) -> list[int]:
    """Measure an asynchronous phase repeatedly after one warm-up."""
    await operation()
    samples: list[int] = []
    for _ in range(repetitions):
        started = time.perf_counter_ns()
        await operation()
        samples.append(time.perf_counter_ns() - started)
    return samples


async def measure_prepared(
    prepare: Callable[[], Awaitable[None]],
    operation: Callable[[], Awaitable[None]],
    repetitions: int,
) -> list[int]:
    """Measure only an operation while rebuilding its state outside the timer."""
    await prepare()
    await operation()
    samples: list[int] = []
    for _ in range(repetitions):
        await prepare()
        started = time.perf_counter_ns()
        await operation()
        samples.append(time.perf_counter_ns() - started)
    return samples


async def event_loop_responsiveness(
    operation: Callable[[], Awaitable[None]],
) -> dict[str, int]:
    """Measure event-loop scheduling gaps while a public operation runs."""
    running = True
    gaps: list[int] = []

    async def heartbeat() -> None:
        previous = time.perf_counter_ns()
        while running:
            await asyncio.sleep(0)
            current = time.perf_counter_ns()
            gaps.append(current - previous)
            previous = current

    task = asyncio.create_task(heartbeat())
    await asyncio.sleep(0)
    started = time.perf_counter_ns()
    try:
        await operation()
    finally:
        running = False
        await task
    return {
        "operation_ns": time.perf_counter_ns() - started,
        "heartbeat_samples": len(gaps),
        "max_event_loop_gap_ns": max(gaps, default=0),
    }


def byte_value(size: int) -> bytes:
    """Create an exact-size opaque value."""
    return bytes(index % 251 for index in range(size))


def json_value(size: int, shape: JsonShape) -> vaultlet.JsonInput:
    """Create a structured JSON value with an approximately requested payload size."""
    if shape == "nodes":
        return {f"field-{index}": index for index in range(max(1, size // 14))}
    overhead = 64
    return {
        "sequence": 42,
        "active": True,
        "payload": "x" * max(0, size - overhead),
        "items": [None, 1, 2.5, "checkpoint"],
    }


async def run_case(case: Case) -> dict[str, object]:
    """Run all public-operation phases for one isolated case."""
    engine = vaultlet.StorageEngine(case.engine)
    value = (
        byte_value(case.size)
        if case.encoding == "bytes"
        else json_value(case.size, case.json_shape)
    )
    with tempfile.TemporaryDirectory(prefix="vaultlet-release-bench-") as directory:
        store = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(Path(directory) / "store", engine=engine),
            key=vaultlet.MasterKey.generate(),
            cleanup_interval=0,
        )
        tenants = [
            store.tenant("shared" if case.tenancy == "one" else f"tenant-{index}")
            for index in range(case.tasks)
        ]
        prefixes = [f"worker-{index}" for index in range(case.tasks)]

        async def for_workers(
            worker: Callable[[vaultlet.TenantStore, str], Awaitable[None]],
        ) -> None:
            await asyncio.gather(
                *(
                    worker(tenant, prefix)
                    for tenant, prefix in zip(tenants, prefixes, strict=True)
                )
            )

        def keys(prefix: str, phase: str) -> list[str]:
            return [f"{prefix}-{phase}-{index}" for index in range(case.batch)]

        async def set_phase(tenant: vaultlet.TenantStore, prefix: str) -> None:
            phase_keys = keys(prefix, "live")
            if case.batch == 1:
                if case.encoding == "bytes":
                    await tenant.set(phase_keys[0], cast("bytes", value))
                else:
                    await tenant.set_json(
                        phase_keys[0], cast("vaultlet.JsonInput", value)
                    )
            elif case.encoding == "bytes":
                await tenant.set_many(dict.fromkeys(phase_keys, cast("bytes", value)))
            else:
                await tenant.set_many_json(
                    dict.fromkeys(phase_keys, cast("vaultlet.JsonInput", value))
                )

        async def hit_phase(tenant: vaultlet.TenantStore, prefix: str) -> None:
            phase_keys = keys(prefix, "live")
            if case.batch == 1:
                observed = (
                    await tenant.get(phase_keys[0])
                    if case.encoding == "bytes"
                    else await tenant.get_json(phase_keys[0])
                )
                if observed is None:
                    raise RuntimeError("warm-hit benchmark missed")
            else:
                observed_many = (
                    await tenant.get_many(phase_keys)
                    if case.encoding == "bytes"
                    else await tenant.get_many_json(phase_keys)
                )
                if len(observed_many) != case.batch:
                    raise RuntimeError("batch warm-hit benchmark missed")

        async def miss_phase(tenant: vaultlet.TenantStore, prefix: str) -> None:
            phase_keys = keys(prefix, "missing")
            if case.batch == 1:
                observed = (
                    await tenant.get(phase_keys[0])
                    if case.encoding == "bytes"
                    else await tenant.get_json(phase_keys[0])
                )
                if observed is not None:
                    raise RuntimeError("miss benchmark unexpectedly hit")
            else:
                observed_many = (
                    await tenant.get_many(phase_keys)
                    if case.encoding == "bytes"
                    else await tenant.get_many_json(phase_keys)
                )
                if observed_many:
                    raise RuntimeError("batch miss benchmark unexpectedly hit")

        async def json_materialize_phase(
            tenant: vaultlet.TenantStore, prefix: str
        ) -> None:
            phase_keys = keys(prefix, "live")
            if case.batch == 1:
                observed = await tenant.get_json(phase_keys[0])
                if not isinstance(observed, (vaultlet.JsonObject, vaultlet.JsonArray)):
                    raise RuntimeError("JSON materialization benchmark missed")
                observed.to_builtin()
                return
            observed_many = await tenant.get_many_json(phase_keys)
            if len(observed_many) != case.batch:
                raise RuntimeError("batch JSON materialization benchmark missed")
            for observed in observed_many.values():
                if not isinstance(observed, (vaultlet.JsonObject, vaultlet.JsonArray)):
                    raise RuntimeError("batch JSON materialization value is not a view")
                observed.to_builtin()

        async def metadata_phase(tenant: vaultlet.TenantStore, prefix: str) -> None:
            if await tenant.metadata(keys(prefix, "live")[0]) is None:
                raise RuntimeError("metadata benchmark missed")

        async def exists_phase(tenant: vaultlet.TenantStore, prefix: str) -> None:
            if not await tenant.exists(keys(prefix, "live")[0]):
                raise RuntimeError("exists benchmark missed")

        async def keys_phase(tenant: vaultlet.TenantStore, prefix: str) -> None:
            if not (await tenant.keys()).keys:
                raise RuntimeError(f"keys benchmark missed for {prefix}")

        async def delete_phase(tenant: vaultlet.TenantStore, prefix: str) -> None:
            phase_keys = keys(prefix, "delete")
            if case.encoding == "bytes":
                await tenant.set_many(dict.fromkeys(phase_keys, cast("bytes", value)))
            else:
                await tenant.set_many_json(
                    dict.fromkeys(phase_keys, cast("vaultlet.JsonInput", value))
                )
            removed = (
                int(await tenant.delete(phase_keys[0]))
                if case.batch == 1
                else await tenant.delete_many(phase_keys)
            )
            if removed != case.batch:
                raise RuntimeError("delete benchmark count mismatch")

        async def seed_expired(phase: str) -> None:
            expires_at = datetime.now(UTC) + timedelta(milliseconds=25)

            async def worker(tenant: vaultlet.TenantStore, prefix: str) -> None:
                phase_keys = keys(prefix, phase)
                if case.encoding == "bytes":
                    await tenant.set_many(
                        dict.fromkeys(phase_keys, cast("bytes", value)),
                        expires_at=expires_at,
                    )
                else:
                    await tenant.set_many_json(
                        dict.fromkeys(phase_keys, cast("vaultlet.JsonInput", value)),
                        expires_at=expires_at,
                    )

            await for_workers(worker)
            await asyncio.sleep(0.035)

        async def lazy_cleanup() -> None:
            async def worker(tenant: vaultlet.TenantStore, prefix: str) -> None:
                phase_keys = keys(prefix, "lazy-expired")
                observed = (
                    await tenant.get_many(phase_keys)
                    if case.encoding == "bytes"
                    else await tenant.get_many_json(phase_keys)
                )
                if observed:
                    raise RuntimeError("lazy cleanup returned expired values")

            await for_workers(worker)

        async def explicit_purge() -> None:
            expected = case.tasks * case.batch
            removed = await store.purge_expired()
            if removed != expected:
                raise RuntimeError(f"purge removed {removed}, expected {expected}")

        tracemalloc.start()
        phase_operations = case.tasks * case.batch
        phases: dict[str, dict[str, float | int]] = {}
        measured_phases: list[tuple[str, Callable[[], Awaitable[None]], int]] = [
            ("miss", lambda: for_workers(miss_phase), phase_operations),
            ("set", lambda: for_workers(set_phase), phase_operations),
            ("warm_hit", lambda: for_workers(hit_phase), phase_operations),
            ("metadata", lambda: for_workers(metadata_phase), case.tasks),
            ("exists", lambda: for_workers(exists_phase), case.tasks),
            ("keys", lambda: for_workers(keys_phase), case.tasks),
            ("delete", lambda: for_workers(delete_phase), phase_operations),
        ]
        if case.encoding == "json":
            measured_phases.append(
                (
                    "json_full_materialization",
                    lambda: for_workers(json_materialize_phase),
                    phase_operations,
                )
            )
        for name, operation, logical_operations in measured_phases:
            phases[name] = distribution(
                await measure(operation, case.repetitions), logical_operations
            )

        lazy_samples = await measure_prepared(
            lambda: seed_expired("lazy-expired"),
            lazy_cleanup,
            case.repetitions,
        )
        phases["ttl_lazy_cleanup"] = distribution(lazy_samples, phase_operations)
        purge_samples = await measure_prepared(
            lambda: seed_expired("purge-expired"),
            explicit_purge,
            case.repetitions,
        )
        phases["explicit_purge"] = distribution(purge_samples, phase_operations)
        responsiveness: dict[str, dict[str, int]] | None = None
        if case.encoding == "json":
            responsiveness = {
                "set": await event_loop_responsiveness(lambda: for_workers(set_phase)),
                "get": await event_loop_responsiveness(lambda: for_workers(hit_phase)),
                "full_materialization": await event_loop_responsiveness(
                    lambda: for_workers(json_materialize_phase)
                ),
            }
        current_allocated, peak_allocated = tracemalloc.get_traced_memory()
        snapshot = tracemalloc.take_snapshot()
        allocation_count = sum(stat.count for stat in snapshot.statistics("filename"))
        tracemalloc.stop()
        await store.aclose()
        peak_rss_raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        peak_rss = peak_rss_raw if sys.platform == "darwin" else peak_rss_raw * 1024
        return {
            "case": asdict(case),
            "phases": phases,
            "memory": {
                "python_current_bytes": current_allocated,
                "python_peak_bytes": peak_allocated,
                "python_allocation_count": allocation_count,
                "peak_rss_bytes": peak_rss,
            },
            "event_loop_responsiveness": responsiveness,
        }


def environment() -> dict[str, object]:
    """Capture the release artifact and host metadata needed to compare runs."""
    extension = Path(_vaultlet.__file__).resolve()
    return {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "python": sys.version,
        "python_executable": sys.executable,
        "vaultlet_version": vaultlet.__version__,
        "native_extension": os.fspath(extension),
        "native_sha256": hashlib.sha256(extension.read_bytes()).hexdigest(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
    }


def quick_cases(repetitions: int) -> list[Case]:
    """Cover both engines, codecs, singular/batch, cleanup, and tenancy quickly."""
    return [
        Case(engine, encoding, size, batch, tasks, tenancy, repetitions)
        for engine in ("sqlite", "redb")
        for encoding in cast("Sequence[Encoding]", ("bytes", "json"))
        for size in (64, 4096)
        for batch in (1, 100)
        for tasks, tenancy in cast(
            "Sequence[tuple[int, Tenancy]]", ((1, "one"), (8, "many"))
        )
        if size * batch * tasks <= MAX_CASE_BYTES
    ]


def target_cases(repetitions: int) -> list[Case]:
    """Measure reference cleanup, live batches, singular values, and JSON."""
    cases = [
        Case(engine, encoding, size, batch, 1, "one", repetitions)
        for engine in ("sqlite", "redb")
        for encoding, size, batch in cast(
            "Sequence[tuple[Encoding, int, int]]",
            (
                ("bytes", 64, 50),
                ("bytes", 64, 100),
                ("bytes", 4096, 1),
                ("json", 4096, 10),
                ("json", 1024 * 1024, 1),
            ),
        )
    ]
    cases.extend(
        Case(engine, "json", 256 * 1024, 1, 1, "one", repetitions, "nodes")
        for engine in ("sqlite", "redb")
    )
    return cases


def report_cases(repetitions: int) -> list[Case]:
    """Cover every requested axis without an unnecessarily Cartesian run."""
    cases: list[Case] = []
    for engine in ("sqlite", "redb"):
        for encoding in cast("Sequence[Encoding]", ("bytes", "json")):
            for size in VALUE_SIZES:
                cases.append(Case(engine, encoding, size, 1, 1, "one", repetitions))
            for batch in BATCH_SIZES:
                cases.append(Case(engine, encoding, 4096, batch, 1, "one", repetitions))
            for tasks in TASK_COUNTS:
                for tenancy in cast("Sequence[Tenancy]", ("one", "many")):
                    cases.append(
                        Case(engine, encoding, 64, 10, tasks, tenancy, repetitions)
                    )
        for batch in (1, 10, 50, 100, 1_000):
            cases.append(Case(engine, "bytes", 64, batch, 1, "one", repetitions))
        cases.append(
            Case(engine, "json", 256 * 1024, 1, 1, "one", repetitions, "nodes")
        )
    return list(dict.fromkeys(cases))


def full_cases(repetitions: int) -> list[Case]:
    """Build the requested release-wheel matrix within a bounded memory envelope."""
    return [
        Case(engine, encoding, size, batch, tasks, tenancy, repetitions)
        for engine in ("sqlite", "redb")
        for encoding in cast("Sequence[Encoding]", ("bytes", "json"))
        for size in VALUE_SIZES
        for batch in BATCH_SIZES
        for tasks in TASK_COUNTS
        for tenancy in cast("Sequence[Tenancy]", ("one", "many"))
        if size * batch * tasks <= MAX_CASE_BYTES
    ]


def run_controller(
    output: Path,
    *,
    quick: bool,
    target: bool,
    report: bool,
    repetitions: int,
) -> None:
    """Run each case in a fresh subprocess so RSS measurements are isolated."""
    extension = Path(_vaultlet.__file__).resolve()
    if "site-packages" not in extension.parts:
        raise RuntimeError(
            "release benchmarks must run from an installed wheel in an isolated "
            "environment"
        )
    if report:
        cases = report_cases(repetitions)
    elif target:
        cases = target_cases(repetitions)
    else:
        cases = quick_cases(repetitions) if quick else full_cases(repetitions)
    output.parent.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, object]] = []
    for index, case in enumerate(cases, start=1):
        print(f"[{index}/{len(cases)}] {case}", flush=True)
        completed = subprocess.run(  # noqa: S603
            [
                sys.executable,
                os.fspath(Path(__file__).resolve()),
                "--case",
                json.dumps(asdict(case), separators=(",", ":")),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        results.append(cast("dict[str, object]", json.loads(completed.stdout)))
    payload = {"environment": environment(), "cases": results}
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def main() -> None:
    """Run a controller matrix or one internal isolated case."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--target", action="store_true")
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--case")
    arguments = parser.parse_args()
    if arguments.case is not None:
        raw = cast("dict[str, object]", json.loads(arguments.case))
        case = Case(
            engine=cast("str", raw["engine"]),
            encoding=cast("Encoding", raw["encoding"]),
            size=cast("int", raw["size"]),
            batch=cast("int", raw["batch"]),
            tasks=cast("int", raw["tasks"]),
            tenancy=cast("Tenancy", raw["tenancy"]),
            repetitions=cast("int", raw["repetitions"]),
            json_shape=cast("JsonShape", raw.get("json_shape", "blob")),
        )
        print(json.dumps(asyncio.run(run_case(case)), sort_keys=True))
        return
    if arguments.output is None:
        parser.error("--output is required for a matrix run")
    run_controller(
        arguments.output,
        quick=arguments.quick,
        target=arguments.target,
        report=arguments.report,
        repetitions=arguments.repetitions,
    )


if __name__ == "__main__":
    main()
