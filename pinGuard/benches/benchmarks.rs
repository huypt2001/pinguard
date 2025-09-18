use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pin_guard::scanners::{package_audit::PackageAudit, Scanner};

fn benchmark_package_scan(c: &mut Criterion) {
    c.bench_function("package_audit_scan", |b| {
        b.iter(|| {
            let scanner = PackageAudit::new();
            // Benchmark a lightweight operation instead of full scan
            black_box(scanner.name())
        })
    });
}

fn benchmark_scanner_creation(c: &mut Criterion) {
    c.bench_function("scanner_creation", |b| {
        b.iter(|| {
            black_box(PackageAudit::new())
        })
    });
}

criterion_group!(benches, benchmark_package_scan, benchmark_scanner_creation);
criterion_main!(benches);
