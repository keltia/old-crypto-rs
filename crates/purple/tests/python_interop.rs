//! Cross-implementation test vectors from Brian Neal's Python PURPLE simulator.
//!
//! Source: https://github.com/gremmie/purple/blob/master/README.rst
//! "Command-line Usage" example, ungrouped output (v1.0.1).
//!
//! These expectations were published independently of old-crypto-rs. They are
//! intentionally hard-coded, rather than computed using the Rust implementation.
//! The reference CLI filters a human-readable sentence; here its *already
//! normalized* uppercase plaintext is supplied directly.

use purple::{PurpleAlphabet, PurpleMachine, PurpleMotion, SwitchPosition, TwentiesSwitchId};

const ALPHABET: &str = "NOKTYUXEQLHBRMPDICJASVWGZF";
const PLAINTEXT: &[u8] = b"THEPURPLEMACHINEISNOWONLINE";
const CIPHERTEXT: &[u8] = b"OGIVTSIAAHMWMHTVIBYYJUOJFUE";

fn python_readme_machine() -> PurpleMachine {
    use TwentiesSwitchId::{One, Three, Two};
    let pos = |n| SwitchPosition::new(n).unwrap();
    // Python key-sheet setting 9-1,24,6-23: fast #2, middle #3, slow #1.
    PurpleMachine::new(
        PurpleAlphabet::new(ALPHABET).unwrap(),
        pos(9),
        [pos(1), pos(24), pos(6)],
        PurpleMotion::new(Two, Three, One).unwrap(),
    )
}

#[test]
fn python_readme_encipher_vector() {
    assert_eq!(PLAINTEXT.len(), CIPHERTEXT.len());
    assert_eq!(python_readme_machine().encipher_bytes(PLAINTEXT).unwrap(), CIPHERTEXT);
}

#[test]
fn python_readme_decipher_vector() {
    assert_eq!(python_readme_machine().decipher_bytes(CIPHERTEXT).unwrap(), PLAINTEXT);
}

#[test]
fn python_readme_streaming_matches_independent_vector() {
    let mut machine = python_readme_machine();
    let mut output = Vec::new();
    // Several call boundaries, including switches crossing position 25.
    for chunk in PLAINTEXT.chunks(7) {
        output.extend(machine.encipher_bytes(chunk).unwrap());
    }
    assert_eq!(output, CIPHERTEXT);
    machine.reset();
    assert_eq!(machine.encipher_bytes(PLAINTEXT).unwrap(), CIPHERTEXT);
}
