//! Divan benchmarks for the alphabetic SG-41 cipher machine.
//!
//! Run with `cargo bench -p sg-41 --bench sg41`.
//!
//! The historical key is validated outside the timed cipher operations.
//! Construction and configuration validation have separate benchmarks.

use divan::{Bencher, black_box};
use old_crypto_rs::Block;
use sg_41::{SG41, Sg41Config, WHEEL_COUNT, WindowLabel};

const REFERENCE_PINS: [&str; WHEEL_COUNT] = [
    "0001101011000100010001101",
    "0110100100001011100101100",
    "11001001000100100100010",
    "01001000111010001110010",
    "001001001010000101011010",
    "011001100110001011010100",
];

const REFERENCE_WINDOWS: [WindowLabel; WHEEL_COUNT] = [
    WindowLabel::Letter('A'),
    WindowLabel::Letter('B'),
    WindowLabel::Letter('C'),
    WindowLabel::Letter('D'),
    WindowLabel::Number(1),
    WindowLabel::Number(0),
];

fn reference_config() -> Sg41Config {
    Sg41Config::from_key_settings(REFERENCE_WINDOWS, REFERENCE_PINS)
        .expect("valid published SG-41 key")
}

fn letters(len: usize) -> Vec<u8> {
    (0..len).map(|index| b'A' + (index % 26) as u8).collect()
}

/// Measures validation and construction of the six-wheel key configuration.
#[divan::bench]
fn validate_config(bencher: Bencher) {
    bencher.bench(|| {
        black_box(
            Sg41Config::from_key_settings(
                black_box(REFERENCE_WINDOWS),
                black_box(REFERENCE_PINS),
            )
            .expect("valid historical key"),
        )
    });
}

/// Builds a fresh stateful core from a previously validated key.
#[divan::bench]
fn build_core(bencher: Bencher) {
    let config = reference_config();

    bencher.bench(|| black_box(black_box(&config).build_core()));
}

/// One stateful character conversion, with setup excluded from timing.
#[divan::bench]
fn encipher_character(bencher: Bencher) {
    let config = reference_config();

    bencher
        .with_inputs(|| config.build_core())
        .bench_values(|mut core| black_box(core.encipher_char(black_box('S'))));
}

/// One stateful character decryption, with setup excluded from timing.
#[divan::bench]
fn decipher_character(bencher: Bencher) {
    let config = reference_config();

    bencher
        .with_inputs(|| config.build_core())
        .bench_values(|mut core| black_box(core.decipher_char(black_box('I'))));
}

/// Continuous processing by one stateful core; includes no key validation.
#[divan::bench(args = [32, 256, 4096])]
fn stateful_encipher(bencher: Bencher, len: usize) {
    let config = reference_config();
    let input = letters(len);

    bencher
        .with_inputs(|| config.build_core())
        .bench_values(|mut core| {
            for &byte in black_box(&input) {
                black_box(core.encipher_char(byte as char).expect("ASCII letter"));
            }
        });
}

/// Shared `Block` interface, including its documented per-call reset.
#[divan::bench(args = [32, 256, 4096])]
fn block_encrypt(bencher: Bencher, len: usize) {
    let machine = SG41::new(reference_config());
    let plaintext = letters(len);

    bencher
        .with_inputs(|| vec![0_u8; len])
        .bench_values(|mut output| {
            black_box(machine.encrypt(black_box(&mut output), black_box(&plaintext)))
        });
}

/// Decryption through `Block`, with ciphertext prepared outside timing.
#[divan::bench(args = [32, 256, 4096])]
fn block_decrypt(bencher: Bencher, len: usize) {
    let machine = SG41::new(reference_config());
    let plaintext = letters(len);
    let mut ciphertext = vec![0_u8; len];
    machine.encrypt(&mut ciphertext, &plaintext);

    bencher
        .with_inputs(|| vec![0_u8; len])
        .bench_values(|mut output| {
            black_box(machine.decrypt(black_box(&mut output), black_box(&ciphertext)))
        });
}

fn main() {
    divan::main();
}
