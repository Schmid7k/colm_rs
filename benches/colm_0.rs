#[allow(dead_code)]
mod consts;

use aes::cipher::generic_array::GenericArray;
use colm::crypto_aead_encrypt;
use consts::KB;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use criterion_cycles_per_byte::CyclesPerByte;
use rand::rngs::OsRng;
use rand::RngCore;

fn bench(c: &mut Criterion<CyclesPerByte>) {
    let mut group = c.benchmark_group("colm-0");
    let mut rng = OsRng;
    let ad = [0u8; 16];
    let nonce = [0u8; 8];
    let mut tmp = [0u8; 16];
    rng.fill_bytes(&mut tmp);
    let key = GenericArray::from(tmp);

    for size in &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB] {
        let mut m = vec![0; *size];
        let mut c = vec![0; size + 16];
        rng.fill_bytes(&mut m);

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(BenchmarkId::new("encrypt-simple", size), |b| {
            b.iter(|| unsafe { crypto_aead_encrypt(&mut c, &m, &ad, &nonce, &key) });
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
