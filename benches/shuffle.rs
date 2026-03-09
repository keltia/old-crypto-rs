use divan::bench;
use old_crypto_rs::helpers::{shuffle, SC_ALPHABET};

fn main() {
    divan::main();
}

const KEY: &str = "ARABESQUE";

#[bench]
fn bench_shuffle() {
    shuffle(KEY, SC_ALPHABET);
}
