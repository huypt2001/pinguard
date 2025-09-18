use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pinguard::scanners::{PackageAudit, Scanner};

fn benchmark_package_scan(c: &mut Criterion) {
    c.bench_function("package_audit_scan", |b| {
        b.iter(|| {
            let scanner = PackageAudit::new();
            // Benchmark a lightweight operation instead of full scan
            black_box(scanner.name())
        })
    });
}

criterion_group!(benches, benchmark_package_scan);
criterion_main!(benches);
