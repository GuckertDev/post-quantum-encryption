use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use post_quantum_encryption::*;
use tempfile::NamedTempFile;

fn bench_encrypt_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt_decrypt");
    let sizes = vec![1_000, 1_000_000]; // 1KB, 1MB
    let mode = Mode::Copy;

    for size in sizes {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();
        let data = vec![0u8; size];
        std::fs::write(path, &data).unwrap();

        group.bench_with_input(BenchmarkId::new("encrypt", size), &size, |b, _| {
            b.iter(|| process_file_encrypt(path, &mode, ENCRYPTION_EXTENSION, false, None, true).unwrap());
        });

        process_file_encrypt(path, &mode, ENCRYPTION_EXTENSION, false, None, true).unwrap();
        let enc_path = path.with_extension(ENCRYPTION_EXTENSION);

        group.bench_with_input(BenchmarkId::new("decrypt", size), &size, |b, _| {
            b.iter(|| process_file_decrypt(&enc_path, &mode, "", false, None, true).unwrap());
        });
    }
    group.finish();
}

criterion_group!(benches, bench_encrypt_decrypt);
criterion_main!(benches);