//! Divan benchmarks for the M-209 cipher machine.
//!
//! Run with `cargo bench -p m209 --bench m209`.
//!
//! These benchmarks use the published TM 11-380 (1944) sample key. Key
//! parsing/validation is outside timed conversions unless explicitly stated.

use divan::{Bencher, black_box};
use m209::{Contact, M209, M209Config, fixtures::{MANUAL_1944_PINS, manual_1944_drum}};
use old_crypto_rs::Block;

fn reference_config() -> M209Config {
    M209Config::from_letters(MANUAL_1944_PINS, "AAAAAA", manual_1944_drum())
        .expect("valid 1944 machine key")
}

fn contacts(len: usize) -> Vec<Contact> {
    (0..len)
        .map(|index| Contact::new((index % 26) as u8).expect("valid contact"))
        .collect()
}

fn letters(len: usize) -> Vec<u8> {
    (0..len).map(|index| b'A' + (index % 26) as u8).collect()
}

/// Includes checked parsing of the six pin patterns and the key's indicators.
#[divan::bench]
fn validate_config(bencher: Bencher) {
    let bars = manual_1944_drum();

    bencher.bench(|| {
        black_box(
            M209Config::from_letters(
                black_box(MANUAL_1944_PINS),
                black_box("AAAAAA"),
                black_box(bars),
            )
            .expect("valid historical key"),
        )
    });
}

/// Constructs a machine from an already-validated configuration.
#[divan::bench]
fn build_machine(bencher: Bencher) {
    let config = reference_config();

    bencher.bench(|| black_box(black_box(&config).build_machine()));
}

/// Reset only: the initial construction and one conversion are not timed.
#[divan::bench]
fn reset_machine(bencher: Bencher) {
    let config = reference_config();

    bencher
        .with_inputs(|| {
            let mut machine = config.build_machine();
            machine.convert_contact(Contact::A);
            machine
        })
        .bench_values(|mut machine| {
            machine.reset();
            black_box(machine.positions())
        });
}

/// One fixed-state conversion; wheel advancement is not included.
#[divan::bench]
fn frozen_convert_contact(bencher: Bencher) {
    let core = reference_config().build_core();

    bencher.bench(|| black_box(core.convert_contact(black_box(Contact::A))));
}

/// One stateful conversion and wheel advancement; machine setup is excluded.
#[divan::bench]
fn stateful_convert_contact(bencher: Bencher) {
    let config = reference_config();

    bencher
        .with_inputs(|| config.build_machine())
        .bench_values(|mut machine| {
            black_box(machine.convert_contact(black_box(Contact::A)))
        });
}

/// Continuous conversion; measures the allocating `convert_contacts` API.
#[divan::bench(args = [32, 256, 4096])]
fn stateful_convert_contacts(bencher: Bencher, len: usize) {
    let config = reference_config();
    let input = contacts(len);

    bencher
        .with_inputs(|| config.build_machine())
        .bench_values(|mut machine| {
            black_box(machine.convert_contacts(black_box(&input)))
        });
}

/// Reuses a caller-owned output buffer; the `Block` facade resets on each call.
#[divan::bench(args = [32, 256, 4096])]
fn block_encrypt(bencher: Bencher, len: usize) {
    let cipher = M209::new(reference_config());
    let input = letters(len);

    bencher
        .with_inputs(|| vec![0_u8; len])
        .bench_values(|mut output| {
            black_box(cipher.encrypt(black_box(&mut output), black_box(&input)))
        });
}

/// Reciprocal `Block` decryption with prepared ciphertext and reusable output.
#[divan::bench(args = [32, 256, 4096])]
fn block_decrypt(bencher: Bencher, len: usize) {
    let cipher = M209::new(reference_config());
    let input = letters(len);
    let mut ciphertext = vec![0_u8; len];
    cipher.encrypt(&mut ciphertext, &input);

    bencher
        .with_inputs(|| vec![0_u8; len])
        .bench_values(|mut output| {
            black_box(cipher.decrypt(black_box(&mut output), black_box(&ciphertext)))
        });
}

fn main() {
    divan::main();
}
