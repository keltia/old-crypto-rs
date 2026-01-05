use divan::bench;
use old_crypto_rs::helpers::{shuffle, shuffle_next};

fn main() {
    divan::main();
}

const KEY: &str = "ARABESQUE";
const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ/-";

#[bench]
fn bench_shuffle() {
    shuffle(KEY, ALPHABET);
}

#[bench]
fn bench_shuffle_next() {
    shuffle_next(KEY, ALPHABET);
}
