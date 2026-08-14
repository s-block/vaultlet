use std::hint::black_box;

use _vaultlet::benchmark_support::{BenchEngine, CryptoHarness, JsonHarness, StoreHarness};
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use tokio::runtime::Runtime;

const VALUE_SIZES: [usize; 4] = [64, 4 * 1024, 1024 * 1024, 10 * 1024 * 1024];

fn crypto_benchmarks(criterion: &mut Criterion) {
    let crypto = CryptoHarness::new();
    let mut encrypt = criterion.benchmark_group("production/envelope-crypto/encrypt");
    for size in VALUE_SIZES {
        encrypt.bench_function(BenchmarkId::from_parameter(size), |bencher| {
            bencher.iter_batched(
                || CryptoHarness::prepare(vec![11_u8; size]),
                |value| black_box(crypto.encrypt_prepared(value)),
                BatchSize::LargeInput,
            );
        });
    }
    encrypt.finish();

    let mut decrypt = criterion.benchmark_group("production/envelope-crypto/decrypt");
    for size in VALUE_SIZES {
        decrypt.bench_function(BenchmarkId::from_parameter(size), |bencher| {
            bencher.iter_batched(
                || crypto.encrypt(vec![11_u8; size]),
                |envelope| black_box(crypto.decrypt(envelope)),
                BatchSize::LargeInput,
            );
        });
    }
    decrypt.finish();

    let mut inspect = criterion.benchmark_group("production/envelope/borrowed-inspect");
    for size in VALUE_SIZES {
        let envelope = crypto.encrypt(vec![11_u8; size]);
        inspect.bench_with_input(
            BenchmarkId::from_parameter(size),
            &envelope,
            |bencher, envelope| {
                bencher.iter(|| black_box(CryptoHarness::inspect(black_box(envelope))));
            },
        );
    }
    inspect.finish();
}

fn storage_benchmarks(criterion: &mut Criterion) {
    production_backend_benchmarks(criterion, "sqlite", BenchEngine::Sqlite);
    production_backend_benchmarks(criterion, "redb", BenchEngine::Redb);
}

fn json_benchmarks(criterion: &mut Criterion) {
    let mut parser = criterion.benchmark_group("production/json/read-index/flat-object");
    for entries in [1_000_usize, 20_000] {
        let encoded = JsonHarness::flat_object(entries);
        parser.bench_function(BenchmarkId::from_parameter(entries), |bencher| {
            bencher.iter_batched(
                || encoded.clone(),
                |value| black_box(JsonHarness::parse(value)),
                BatchSize::LargeInput,
            );
        });
    }
    parser.finish();
}

fn production_backend_benchmarks(criterion: &mut Criterion, name: &str, engine: BenchEngine) {
    let runtime = Runtime::new().expect("benchmark runtime");
    let directory = tempfile::tempdir().expect("benchmark directory");
    let store = runtime.block_on(StoreHarness::open(directory.path().join(name), engine));

    for size in VALUE_SIZES {
        runtime.block_on(store.set(
            format!("read-{size}"),
            StoreHarness::prepare_value(vec![13_u8; size]),
        ));
    }
    let mut reads = criterion.benchmark_group(format!("production/{name}/get"));
    for size in VALUE_SIZES {
        reads.bench_function(BenchmarkId::from_parameter(size), |bencher| {
            bencher.iter(|| {
                black_box(runtime.block_on(store.get(format!("read-{size}"))));
            });
        });
    }
    reads.finish();

    let mut writes = criterion.benchmark_group(format!("production/{name}/durable-set"));
    writes.sample_size(10);
    for size in VALUE_SIZES {
        writes.bench_function(BenchmarkId::from_parameter(size), |bencher| {
            bencher.iter_batched(
                || StoreHarness::prepare_value(vec![14_u8; size]),
                |value| runtime.block_on(store.set(format!("write-{size}"), value)),
                BatchSize::LargeInput,
            );
        });
    }
    for batch_size in [1_usize, 10, 100, 1_000] {
        writes.bench_function(BenchmarkId::new("batch-4KiB", batch_size), |bencher| {
            bencher.iter_batched(
                || {
                    (0..batch_size)
                        .map(|index| {
                            (
                                format!("batch-{index}"),
                                StoreHarness::prepare_value(vec![15_u8; 4096]),
                            )
                        })
                        .collect()
                },
                |values| runtime.block_on(store.set_many(values)),
                BatchSize::LargeInput,
            );
        });
    }
    writes.finish();
    runtime.block_on(store.close());
}

criterion_group!(
    benches,
    crypto_benchmarks,
    json_benchmarks,
    storage_benchmarks
);
criterion_main!(benches);
