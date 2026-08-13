//! Independent known-answer/interoperability tests for CSP-889.
//!
//! These tests are intentionally kept separate from the internal unit fixtures.
//! Their expected values come from Joseph Dunn's C++ port of Rich Pekelney's
//! Java ECM Mark II simulator. Dunn's `test_sigaba/main.cpp` states that these
//! cases compare the C++ output against the Java simulator.
//!
//! Reference:
//! <https://github.com/JoeDunnStable/sigaba>
//!
//! Default CSP-889 reference key:
//!
//! ```text
//! cipher order:  0N 1N 2N 3N 4N
//! control order: 5N 6N 7N 8N 9N
//! index order:   0N 1N 2N 3N 4N
//! cipher pos:    O O O O O
//! control pos:   O O O O O
//! index pos:     0 0 0 0 0
//! ```

use super::{
    alphabet_rotor::Orientation,
    config::{IndexRotorSetting, LargeRotorSetting, SigabaConfig},
    contact::{Position10, Position26},
    data::{IndexRotorId, LargeRotorId, LargeRotorSet},
    text::{decipher_text, encipher_text},
};

fn lid(value: u8) -> LargeRotorId {
    LargeRotorId::new(value).unwrap()
}

fn iid(value: u8) -> IndexRotorId {
    IndexRotorId::new(value).unwrap()
}

fn p26(letter: u8) -> Position26 {
    Position26::new(letter - b'A').unwrap()
}

fn p10(value: u8) -> Position10 {
    Position10::new(value).unwrap()
}

fn large(id: u8, letter: u8) -> LargeRotorSetting {
    LargeRotorSetting::new(
        lid(id),
        p26(letter),
        Orientation::Normal,
    )
}

fn idx(id: u8, position: u8) -> IndexRotorSetting {
    IndexRotorSetting::new(iid(id), p10(position))
}

fn reference_zeroized_config() -> SigabaConfig {
    SigabaConfig::new(
        LargeRotorSet::PekelneyReference,
        [
            large(0, b'O'),
            large(1, b'O'),
            large(2, b'O'),
            large(3, b'O'),
            large(4, b'O'),
        ],
        [
            large(5, b'O'),
            large(6, b'O'),
            large(7, b'O'),
            large(8, b'O'),
            large(9, b'O'),
        ],
        [
            idx(0, 0),
            idx(1, 0),
            idx(2, 0),
            idx(3, 0),
            idx(4, 0),
        ],
    )
    .unwrap()
}

fn reference_abcde_config() -> SigabaConfig {
    SigabaConfig::new(
        LargeRotorSet::PekelneyReference,
        [
            large(0, b'A'),
            large(1, b'B'),
            large(2, b'C'),
            large(3, b'D'),
            large(4, b'E'),
        ],
        [
            large(5, b'A'),
            large(6, b'B'),
            large(7, b'C'),
            large(8, b'D'),
            large(9, b'E'),
        ],
        [
            idx(0, 0),
            idx(1, 0),
            idx(2, 0),
            idx(3, 0),
            idx(4, 0),
        ],
    )
    .unwrap()
}

fn positions_to_string(positions: [u8; 5]) -> String {
    positions
        .into_iter()
        .map(|position| char::from(b'A' + position))
        .collect()
}

#[test]
fn pekelney_dunn_csp889_known_answer_hello_world() {
    let config = reference_zeroized_config();
    let mut machine = config.build_core().unwrap();

    let ciphertext = encipher_text(&mut machine, "HELLO WORLD").unwrap();

    assert_eq!(ciphertext, "FLQGFQUEQCH");
}

#[test]
fn pekelney_dunn_csp889_known_answer_deciphers_hello_world() {
    let config = reference_zeroized_config();
    let mut machine = config.build_core().unwrap();

    let plaintext = decipher_text(&mut machine, "FLQGF QUEQC H").unwrap();

    assert_eq!(plaintext, "HELLO WORLD");
}

#[test]
fn pekelney_dunn_csp889_abcde_known_answer() {
    let config = reference_abcde_config();
    let mut machine = config.build_core().unwrap();

    let ciphertext = encipher_text(&mut machine, "HELLO WORLD").unwrap();

    assert_eq!(ciphertext, "PHXZJOJXYVA");
}

#[test]
fn pekelney_dunn_zeroized_cipher_position_trace_matches() {
    let expected = [
        "NONON",
        "MOMOM",
        "MOLNL",
        "LOLMK",
        "KOKMJ",
        "JNKLJ",
        "IMJKJ",
        "HMJJJ",
        "GLJJI",
        "FLIIH",
    ];

    let config = reference_zeroized_config();
    let mut machine = config.build_core().unwrap();

    for (input, expected_positions) in b"HELLOWORLD".iter().zip(expected) {
        let plaintext = char::from(*input).to_string();
        let _ = encipher_text(&mut machine, &plaintext).unwrap();

        assert_eq!(
            positions_to_string(machine.cipher_positions()),
            expected_positions,
        );
    }
}

#[test]
fn pekelney_dunn_zeroized_control_position_trace_matches() {
    let expected = [
        "ONNNO",
        "ONMNO",
        "ONLNO",
        "ONKNO",
        "ONJNO",
        "ONINO",
        "ONHNO",
        "ONGNO",
        "ONFNO",
        "ONENO",
    ];

    let config = reference_zeroized_config();
    let mut machine = config.build_core().unwrap();

    for (input, expected_positions) in b"HELLOWORLD".iter().zip(expected) {
        let plaintext = char::from(*input).to_string();
        let _ = encipher_text(&mut machine, &plaintext).unwrap();

        assert_eq!(
            positions_to_string(machine.control_positions()),
            expected_positions,
        );
    }
}

#[test]
fn known_answer_grouping_is_presentation_only() {
    let config = reference_zeroized_config();

    let mut grouped = config.build_core().unwrap();
    let grouped_plain =
        decipher_text(&mut grouped, "FLQGF QUEQC H").unwrap();

    let mut ungrouped = config.build_core().unwrap();
    let ungrouped_plain =
        decipher_text(&mut ungrouped, "FLQGFQUEQCH").unwrap();

    assert_eq!(grouped_plain, "HELLO WORLD");
    assert_eq!(ungrouped_plain, "HELLO WORLD");
    assert_eq!(grouped.cipher_positions(), ungrouped.cipher_positions());
    assert_eq!(grouped.control_positions(), ungrouped.control_positions());
}
