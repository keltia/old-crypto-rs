//! Frozen M-209 reciprocal letter conversion.
//!
//! A frozen core inspects the six currently sensed pins and the lug drum
//! without advancing any wheel. The complete machine cycle is Step 8.
//!
//! With `A = 0`, the transformation is `(25 - input + displacement) mod 26`.
//! The *positive* displacement is essential: 20 engaged bars convert A to T
//! in the 1944 War Department example.

use crate::{Contact, LugDrum, WheelBank};

/// The six wheel positions and drum settings at one mechanical instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct M209Core {
    wheels: WheelBank,
    drum: LugDrum,
}

impl M209Core {
    /// Build a stationary cipher core from already validated machine parts.
    pub const fn new(wheels: WheelBank, drum: LugDrum) -> Self {
        Self { wheels, drum }
    }

    pub const fn wheels(&self) -> &WheelBank {
        &self.wheels
    }

    pub const fn drum(&self) -> &LugDrum {
        &self.drum
    }

    /// Active guide arms at the current positions (bit 0 = wheel 1).
    pub fn effective_mask(&self) -> u8 {
        self.wheels.effective_mask()
    }

    /// Actual number of engaged bars, in the range 0..=27.
    pub fn displacement(&self) -> u8 {
        self.drum.displacement(self.effective_mask())
    }

    /// Advance the internal wheel bank after a character has been converted.
    /// Kept crate-private so the public frozen conversion remains non-stepping.
    pub(crate) fn advance_wheels(&mut self) {
        self.wheels.advance();
    }

    /// Encipher or decipher one contact without modifying wheel positions.
    ///
    /// Beaufort reciprocity means the same operation is used in both directions.
    pub fn convert_contact(&self, input: Contact) -> Contact {
        let displacement = self.displacement();
        let output = (25 + displacement - input.index()) % Contact::COUNT;

        Contact::new(output).expect("modulo 26 produces a valid contact")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PinPattern, WheelId, WheelPosition, WHEEL_COUNT};
    use crate::fixtures::{MANUAL_1944_PINS, manual_1944_drum, parse_pin_fixture};

    fn manual_core() -> M209Core {
        let patterns = parse_pin_fixture(MANUAL_1944_PINS).unwrap();
        let positions = core::array::from_fn(|index| {
            WheelId::new(index as u8 + 1)
                .unwrap()
                .position_for_letter('A')
                .unwrap()
        });

        let wheels = WheelBank::new(patterns, positions).unwrap();
        let drum = LugDrum::new(manual_1944_drum());

        M209Core::new(wheels, drum)
    }

    #[test]
    fn historical_first_character_is_a_to_t_without_stepping() {
        let core = manual_core();
        let start = core.wheels().positions();

        assert_eq!(core.effective_mask(), 0b10_1110);
        assert_eq!(core.displacement(), 20);
        assert_eq!(core.convert_contact(Contact::A).letter(), 'T');
        assert_eq!(core.wheels().positions(), start);
    }

    #[test]
    fn reciprocal_at_the_historical_frozen_state_for_every_contact() {
        let core = manual_core();

        for index in 0..Contact::COUNT {
            let original = Contact::new(index).unwrap();
            let ciphertext = core.convert_contact(original);

            assert_eq!(core.convert_contact(ciphertext), original);
        }
    }

    #[test]
    fn conversion_uses_plus_displacement_not_minus() {
        let core = manual_core();

        assert_eq!(core.convert_contact(Contact::from_letter('P').unwrap()).letter(), 'E');
        assert_eq!(core.convert_contact(Contact::from_letter('E').unwrap()).letter(), 'P');
    }

    #[test]
    fn zero_displacement_is_plain_atbash() {
        let patterns: [PinPattern; WHEEL_COUNT] = core::array::from_fn(|index| {
            PinPattern::empty(WheelId::new(index as u8 + 1).unwrap())
        });
        let positions: [WheelPosition; WHEEL_COUNT] = core::array::from_fn(|index| {
            WheelId::new(index as u8 + 1).unwrap().position_for_letter('A').unwrap()
        });

        let core = M209Core::new(
            WheelBank::new(patterns, positions).unwrap(),
            LugDrum::new(manual_1944_drum()),
        );

        assert_eq!(core.displacement(), 0);
        assert_eq!(core.convert_contact(Contact::A).letter(), 'Z');
        assert_eq!(core.convert_contact(Contact::from_letter('Z').unwrap()), Contact::A);
    }

    #[test]
    fn frozen_core_is_deterministic_and_does_not_advance() {
        let core = manual_core();
        let before = core.clone();

        for _ in 0..100 {
            assert_eq!(core.convert_contact(Contact::A).letter(), 'T');
        }

        assert_eq!(core, before);
    }
}
