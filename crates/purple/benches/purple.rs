//! Divan benchmarks for the PURPLE cipher machine.
//! Run: cargo bench -p purple --bench purple

use divan::black_box;
use old_crypto_rs::Block;
use purple::{
    Purple, PurpleAlphabet, PurpleConfig, PurpleCore, PurpleMachine, PurpleMotion,
    SwitchPosition, TwentiesSwitchId,
};

fn config() -> PurpleConfig {
    use TwentiesSwitchId::{One, Three, Two};
    let p = |n| SwitchPosition::new(n).expect("valid historical position");
    PurpleConfig::new(
        PurpleAlphabet::new("NOKTYUXEQLHBRMPDICJASVWGZF")
            .expect("valid historical alphabet"),
        p(9),
        [p(1), p(24), p(6)],
        PurpleMotion::new(Two, Three, One).expect("valid motion assignment"),
    )
}

fn core() -> PurpleCore {
    let cfg = config();
    PurpleCore::new(cfg.alphabet().clone(), cfg.sixes(), cfg.twenties())
}

fn message(n: usize) -> Vec<u8> {
    (0..n).map(|i| b'A' + (i % 26) as u8).collect()
}

// Measures construction of a fresh stateful machine from an already validated
// configuration. Configuration parsing/validation is outside the timed closure.
#[divan::bench]
fn build_machine(bencher: divan::Bencher) {
    let cfg = config();
    bencher.bench(|| black_box(black_box(&cfg).build_machine()));
}

// Reset a machine that has already processed a character. Both construction
// and the advance happen outside the timed closure via Divan's input fixture.
#[divan::bench]
fn reset_machine(bencher: divan::Bencher) {
    let cfg = config();
    bencher
        .with_inputs(|| {
            let mut machine = cfg.build_machine();
            machine.encipher(b'A').expect("valid letter");
            machine
        })
        .bench_values(|mut machine| {
            machine.reset();
            black_box(machine.state())
        });
}

// No stepping and no per-call setup: isolates electrical substitution.
#[divan::bench]
fn frozen_encipher_letter(bencher: divan::Bencher) {
    bencher.with_inputs(core).bench_values(|core| {
        black_box(core.encipher(black_box(b'A')).expect("valid letter"))
    });
}

#[divan::bench]
fn frozen_decipher_letter(bencher: divan::Bencher) {
    bencher.with_inputs(core).bench_values(|core| {
        black_box(core.decipher(black_box(b'Z')).expect("valid letter"))
    });
}

// Each invocation creates its own initial state. The timing includes stepping,
// but not construction, which occurs before divan's measured closure.
#[divan::bench]
fn stateful_encipher_letter(bencher: divan::Bencher) {
    bencher
        .with_inputs(|| config().build_machine())
        .bench_values(|mut machine: PurpleMachine| {
            black_box(machine.encipher(black_box(b'A')).expect("valid letter"))
        });
}

#[divan::bench]
fn stateful_decipher_letter(bencher: divan::Bencher) {
    bencher
        .with_inputs(|| config().build_machine())
        .bench_values(|mut machine: PurpleMachine| {
            black_box(machine.decipher(black_box(b'Z')).expect("valid letter"))
        });
}

// Includes Vec allocation inside the stateful batch API, but not machine setup.
#[divan::bench(args = [32, 256, 4096])]
fn stateful_encipher_bytes(bencher: divan::Bencher, len: usize) {
    let input = message(len);
    bencher
        .with_inputs(|| config().build_machine())
        .bench_values(|mut machine| {
            black_box(machine.encipher_bytes(black_box(&input)).expect("valid plaintext"))
        });
}

// The reusable facade resets state and allocates its output for every call.
#[divan::bench(args = [32, 256, 4096])]
fn facade_encrypt_bytes(bencher: divan::Bencher, len: usize) {
    let input = message(len);
    let cipher = Purple::new(config());
    bencher.bench(|| {
        black_box(cipher.encrypt_bytes(black_box(&input)).expect("valid plaintext"))
    });
}

// Block writes into a caller-owned buffer. Reuse the buffer so this measures
// bounded cipher processing and reset, not allocation of the destination.
#[divan::bench(args = [32, 256, 4096])]
fn block_encrypt(bencher: divan::Bencher, len: usize) {
    let input = message(len);
    let cipher = Purple::new(config());
    bencher
        .with_inputs(|| vec![0_u8; len])
        .bench_values(|mut output| {
            black_box(cipher.encrypt(black_box(&mut output), black_box(&input)))
        });
}

fn main() {
    divan::main();
}
