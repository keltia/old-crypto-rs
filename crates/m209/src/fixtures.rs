//! Published machine-key fixtures, kept separate from the cipher mechanism.
//!
//! The historical sample is transcribed from US War Department TM 11-380
//! (17 March 1944), printed pages 13 (Table I) and 15 (Table II).
//! These are SAMPLE KEY SETTINGS, not fixed machine wiring.

use crate::{DRUM_BAR_COUNT, DrumBar, KeyError, Lug, PinPattern, WHEEL_COUNT, WheelId};

/// Effective-pin letters for physical wheels 1 through 6, Table I, p. 13.
pub const MANUAL_1944_PINS: [&str; WHEEL_COUNT] = [
    "ABDHIKMNSTVW",
    "ADEGJKLORSUX",
    "ABGHJLMNRSTUX",
    "CEFHIMNPSTU",
    "BDEFHIMNPS",
    "ABDHKNOQ",
];

/// Ordered left/right lug positions of all drum bars, Table II, p. 15.
/// Zero denotes the neutral position; bar numbering begins at one.
pub const MANUAL_1944_LUGS: [(u8, u8); DRUM_BAR_COUNT] = [
    (3, 6), (0, 6), (1, 6), (1, 5), (4, 5),
    (0, 4), (0, 4), (0, 4), (0, 4),
    (2, 0), (2, 0), (2, 0), (2, 0), (2, 0),
    (2, 0), (2, 0), (2, 0), (2, 0), (2, 0),
    (2, 5), (2, 5),
    (0, 5), (0, 5), (0, 5), (0, 5), (0, 5), (0, 5),
];

/// TM 11-380, p. 15, setup-check output with the two tables above.
/// This is NOT executed as a cipher known-answer test until Step 9.
pub const MANUAL_1944_CHECK: &str = "TNJUWAUQTKCZKNUTOTBCWARMIO";

/// Brian Neal's published Python `m209` interoperability fixture.
/// This is a distinct key, NOT the historical manual key.
/// https://m209.readthedocs.io/en/latest/m209.html
pub const PYTHON_REFERENCE_PINS: [&str; WHEEL_COUNT] = [
    "FGIKOPRSUVWYZ",
    "DFGKLMOTUY",
    "ADEFGIORTUVX",
    "ACFGHILMRSU",
    "BCDEFJKLPS",
    "EFGHIJLMNP",
];

pub const PYTHON_REFERENCE_LUGS: &[(u8, u8)] = &[
    (1, 0), (2, 0), (2, 0), (0, 3), (0, 5),
    (0, 5), (0, 5), (0, 6), (2, 4), (3, 6),
];

pub const PYTHON_REFERENCE_START: &str = "FFEGJP";
pub const PYTHON_REFERENCE_PLAINTEXT: &str = "THE PIZZA HAS ARRIVED";
pub const PYTHON_REFERENCE_CIPHERTEXT: &str = "QBCHU WCCDI YFNCH LOZJY G";

/// Parse a published pin key into checked, wheel-bound patterns.
pub fn parse_pin_fixture(
    letters: [&str; WHEEL_COUNT],
) -> Result<[PinPattern; WHEEL_COUNT], KeyError> {
    // Constructing all wheels is infallible because these indices are fixed.
    let mut patterns = core::array::from_fn(|index| {
        let wheel = WheelId::new(index as u8 + 1).expect("six valid physical wheels");
        PinPattern::empty(wheel)
    });

    for (index, pattern) in patterns.iter_mut().enumerate() {
        *pattern = PinPattern::from_letters(pattern.wheel(), letters[index])?;
    }

    Ok(patterns)
}

/// Parse the historical 27-bar sample key into ordered checked lug pairs.
pub fn manual_1944_drum() -> [DrumBar; DRUM_BAR_COUNT] {
    MANUAL_1944_LUGS.map(|(left, right)| {
        DrumBar::new(
            Lug::new(left).expect("validated manual left lug"),
            Lug::new(right).expect("validated manual right lug"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_pin_table_validates_against_every_historical_wheel() {
        let pins = parse_pin_fixture(MANUAL_1944_PINS).unwrap();

        assert_eq!(pins.len(), 6);
        assert_eq!(MANUAL_1944_PINS.map(str::len), [12, 12, 13, 11, 10, 8]);

        for (index, pin) in pins.iter().enumerate() {
            assert_eq!(pin.wheel().number(), index as u8 + 1);
            assert_eq!(pin.bits().count_ones() as usize, MANUAL_1944_PINS[index].len());
        }
    }

    #[test]
    fn manual_lug_table_preserves_all_twenty_seven_physical_bars() {
        let bars = manual_1944_drum();

        assert_eq!(bars.len(), 27);
        assert_eq!(bars[0].left().value(), 3);
        assert_eq!(bars[0].right().value(), 6);
        assert_eq!(bars[18].left().value(), 2);
        assert_eq!(bars[19].right().value(), 5);
        assert_eq!(bars[26].left().value(), 0);
        assert_eq!(bars[26].right().value(), 5);

        for (index, bar) in bars.iter().enumerate() {
            assert_eq!((bar.left().value(), bar.right().value()), MANUAL_1944_LUGS[index]);
        }
    }

    #[test]
    fn manual_check_is_exactly_twenty_six_letters() {
        assert_eq!(MANUAL_1944_CHECK.len(), 26);
        assert!(MANUAL_1944_CHECK.bytes().all(|letter| letter.is_ascii_uppercase()));
    }

    #[test]
    fn python_reference_is_independently_keyed_and_well_formed() {
        let pins = parse_pin_fixture(PYTHON_REFERENCE_PINS).unwrap();
        assert_eq!(pins.len(), 6);
        assert_ne!(PYTHON_REFERENCE_PINS, MANUAL_1944_PINS);
        assert_eq!(PYTHON_REFERENCE_START.len(), 6);
        assert_eq!(PYTHON_REFERENCE_LUGS.len(), 10);

        for (left, right) in PYTHON_REFERENCE_LUGS {
            assert!(Lug::new(*left).is_some());
            assert!(Lug::new(*right).is_some());
        }
    }

    #[test]
    fn invalid_published_pin_letter_is_not_silently_ignored() {
        let mut invalid = MANUAL_1944_PINS;
        invalid[1] = "AW"; // Wheel 2 has no W position.
        assert!(parse_pin_fixture(invalid).is_err());
    }
}
