use colm_rs::{
    aead::{Aead, KeyInit},
    AeadInPlace, Colm0Aes128,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use criterion_cycles_per_byte::CyclesPerByte;
use rand::rngs::OsRng;
use rand::RngCore;

pub const KB: usize = 1024;

fn bench(c: &mut Criterion<CyclesPerByte>) {
    let mut group = c.benchmark_group("colm0dec");
    let mut rng = OsRng;
    let ad = [0u8; 0];
    let nonce = [0u8; 8];
    let mut key = [0u8; 16];
    rng.fill_bytes(&mut key);
    let cipher = Colm0Aes128::new(&key.into());

    for size in &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB] {
        let mut m = vec![0; *size];
        rng.fill_bytes(&mut m);
        let mut buf = cipher
            .encrypt(&nonce.into(), m.as_slice())
            .expect("Encryption failure");

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(BenchmarkId::new("decrypt", size), |b| {
            b.iter(|| {
                cipher
                    .decrypt(&nonce.into(), buf.as_slice())
                    .expect("Decryption error")
            });
        });

        buf = cipher
            .encrypt(&nonce.into(), m.as_slice())
            .expect("Encryption failure");

        group.bench_function(BenchmarkId::new("decrypt-into", size), |b| {
            b.iter(|| {
                cipher
                    .encrypt_in_place_detached(&nonce.into(), &ad, buf.as_mut_slice())
                    .expect("Decryption error")
            });
        });
    }

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench
);

criterion_main!(benches);
