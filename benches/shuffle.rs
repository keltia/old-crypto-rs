use std::hint::black_box;

use divan::{Bencher, bench};

use old_crypto_rs::helpers::{SC_ALPHABET, shuffle, transp_shuffle};

fn main() {
    divan::main();
}

const KEY: &str = "ARABESQUE";

#[bench]
fn bench_shuffle(bencher: Bencher) {
    bencher.bench_local(|| {
        black_box(shuffle(KEY, SC_ALPHABET));
    });
}

#[bench]
fn bench_transp_shuffle(bencher: Bencher) {
    bencher.bench_local(|| {
        black_box(transp_shuffle(KEY, SC_ALPHABET));
    });
}
