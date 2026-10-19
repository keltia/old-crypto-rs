//! Independently published M-209 known-answer example from Brian Neal's
//! Python `m209` 1.0.0 documentation (M209 class, "Example").
//!
//! https://m209.readthedocs.io/en/latest/m209.html
//!
//! This key is entirely separate from TM 11-380's 1944 sample. The Python
//! implementation interprets input spaces as Z, emits five-letter groups,
//! and (by default) converts decoded Z characters to spaces. These tests use
//! raw machine contacts so formatting never changes machine state.

use m209::fixtures::{
    PYTHON_REFERENCE_CIPHERTEXT, PYTHON_REFERENCE_PINS, PYTHON_REFERENCE_PLAINTEXT,
    PYTHON_REFERENCE_START, parse_pin_fixture, python_reference_drum,
};
use m209::{Contact, LugDrum, M209Core, M209Machine, WHEEL_COUNT, WheelBank, WheelId};

/// The input to the raw M-209 after the reference library's space substitution.
const RAW_PLAINTEXT: &str = "THEZPIZZAZHASZARRIVED";

/// Published five-letter ciphertext groups, with separators removed.
const RAW_CIPHERTEXT: &str = "QBCHUWCCDIYFNCHLOZJYG";

fn reference_machine() -> M209Machine {
    let patterns = parse_pin_fixture(PYTHON_REFERENCE_PINS)
        .expect("valid published reference pin settings");

    let positions = core::array::from_fn(|index| {
        let wheel = WheelId::new(index as u8 + 1).expect("six physical wheels");
        let letter = PYTHON_REFERENCE_START.as_bytes()[index] as char;

        wheel.position_for_letter(letter).expect("valid published wheel indicator")
    });

    let wheels = WheelBank::new(patterns, positions).expect("valid reference wheel bank");
    let drum = LugDrum::new(python_reference_drum());

    M209Machine::new(M209Core::new(wheels, drum))
}

fn contacts(input: &str) -> Vec<Contact> {
    input.chars()
        .map(|letter| Contact::from_letter(letter).expect("uppercase raw machine contact"))
        .collect()
}

fn letters(input: &[Contact]) -> String {
    input.iter().copied().map(Contact::letter).collect()
}

#[test]
fn python_published_ciphertext_matches_raw_machine_contacts() {
    assert_eq!(PYTHON_REFERENCE_PLAINTEXT.replace(' ', "Z"), RAW_PLAINTEXT);
    assert_eq!(PYTHON_REFERENCE_CIPHERTEXT.replace(' ', ""), RAW_CIPHERTEXT);

    let mut machine = reference_machine();
    assert_eq!(machine.core().wheels().visible_letters(), PYTHON_REFERENCE_START);

    let actual = machine.convert_contacts(&contacts(RAW_PLAINTEXT));
    assert_eq!(letters(&actual), RAW_CIPHERTEXT);
}

#[test]
fn python_published_ciphertext_deciphers_without_lossy_text_mapping() {
    let mut machine = reference_machine();
    let actual = machine.convert_contacts(&contacts(RAW_CIPHERTEXT));

    assert_eq!(letters(&actual), RAW_PLAINTEXT);
    // The reference Python default renders every Z as a space, including
    // the two literal Z letters in PIZZA; raw decoding must not do that.
    assert_eq!(letters(&actual).replace('Z', " "), "THE PI  A HAS ARRIVED");
}

#[test]
fn python_reference_streaming_and_reset_match_published_ciphertext() {
    let input = contacts(RAW_PLAINTEXT);
    let mut machine = reference_machine();

    let mut output = machine.convert_contacts(&input[..5]);
    output.extend(machine.convert_contacts(&input[5..13]));
    output.extend(machine.convert_contacts(&input[13..]));

    assert_eq!(letters(&output), RAW_CIPHERTEXT);
    assert_eq!(machine.positions().len(), WHEEL_COUNT);

    machine.reset();
    assert_eq!(machine.core().wheels().visible_letters(), PYTHON_REFERENCE_START);
    assert_eq!(letters(&machine.convert_contacts(&input)), RAW_CIPHERTEXT);
}

#[test]
fn python_reference_reciprocity_holds_for_fresh_machines() {
    let mut encoder = reference_machine();
    let mut decoder = reference_machine();

    let ciphertext = encoder.convert_contacts(&contacts(RAW_PLAINTEXT));
    let plaintext = decoder.convert_contacts(&ciphertext);

    assert_eq!(letters(&plaintext), RAW_PLAINTEXT);
    assert_eq!(encoder.positions(), decoder.positions());
}
