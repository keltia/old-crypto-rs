//! Full-machine known-answer tests from US War Department TM 11-380 (1944).
//!
//! Table I (printed p. 13) supplies the effective pins, Table II (printed
//! p. 15) the 27 lug settings and the published 26-letter setup check.
//! These tests deliberately use the literal published expected ciphertext.

use m209::fixtures::{
    MANUAL_1944_CHECK, MANUAL_1944_PINS, manual_1944_drum, parse_pin_fixture,
};
use m209::{Contact, LugDrum, M209Core, M209Machine, WheelBank, WheelId, WHEEL_COUNT};

const PLAINTEXT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAA";
const PUBLISHED_CIPHERTEXT: &str = "TNJUWAUQTKCZKNUTOTBCWARMIO";

fn historical_machine() -> M209Machine {
    let pins = parse_pin_fixture(MANUAL_1944_PINS).expect("valid historical pin table");

    let positions = core::array::from_fn(|index| {
        WheelId::new(index as u8 + 1)
            .expect("valid wheel")
            .position_for_letter('A')
            .expect("all six wheels have position A")
    });

    let wheels = WheelBank::new(pins, positions).expect("valid historical wheel bank");
    let drum = LugDrum::new(manual_1944_drum());

    M209Machine::new(M209Core::new(wheels, drum))
}

fn contacts(text: &str) -> Vec<Contact> {
    text.chars()
        .map(|letter| Contact::from_letter(letter).expect("uppercase historical test letter"))
        .collect()
}

fn letters(contacts: &[Contact]) -> String {
    contacts.iter().copied().map(Contact::letter).collect()
}

#[test]
fn manual_1944_full_26_character_known_answer() {
    assert_eq!(MANUAL_1944_CHECK, PUBLISHED_CIPHERTEXT);

    let mut machine = historical_machine();
    assert_eq!(machine.core().wheels().visible_letters(), "AAAAAA");
    assert_eq!(machine.core().wheels().sensed_letters(), "PONMLK");
    assert_eq!(machine.core().effective_mask(), 0b10_1110);
    assert_eq!(machine.core().displacement(), 20);

    let ciphertext = machine.convert_contacts(&contacts(PLAINTEXT));

    assert_eq!(letters(&ciphertext), PUBLISHED_CIPHERTEXT);
}

#[test]
fn manual_1944_deciphers_published_check_reciprocally() {
    let mut machine = historical_machine();

    let plaintext = machine.convert_contacts(&contacts(PUBLISHED_CIPHERTEXT));

    assert_eq!(letters(&plaintext), PLAINTEXT);
}

#[test]
fn manual_1944_streaming_and_reset_preserve_published_check() {
    let mut machine = historical_machine();
    let input = contacts(PLAINTEXT);

    let mut first = machine.convert_contacts(&input[..7]);
    first.extend(machine.convert_contacts(&input[7..19]));
    first.extend(machine.convert_contacts(&input[19..]));

    assert_eq!(letters(&first), PUBLISHED_CIPHERTEXT);

    machine.reset();
    assert_eq!(machine.core().wheels().visible_letters(), "AAAAAA");
    assert_eq!(letters(&machine.convert_contacts(&input)), PUBLISHED_CIPHERTEXT);
}

#[test]
fn manual_1944_stepping_state_after_26_letters() {
    let mut machine = historical_machine();
    machine.convert_contacts(&contacts(PLAINTEXT));

    // The first wheel has length 26; the others retain their individual periods.
    assert_eq!(machine.core().wheels().visible_letters(), "A B D F H J".replace(' ', ""));
    assert_eq!(machine.positions().len(), WHEEL_COUNT);
}
