//! Validated M-209 key assembly, separate from mechanical operation.
//!
//! Pin patterns and indicator positions are ordered by physical wheel (1–6).
//! Drum bars are ordered by physical bar (1–27). The model permits neutral
//! lug settings, as used by the published Python interoperability example.

use crate::{
    DRUM_BAR_COUNT, DrumBar, KeyError, LugDrum, M209Core, M209Machine,
    PinPattern, WHEEL_COUNT, WheelBank, WheelId, WheelPosition,
};

/// A complete, validated M-209 machine key and its initial indicator positions.
///
/// The typed fields cannot be constructed with out-of-range contacts, pins,
/// or lugs. `new` also checks their physical wheel ordering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct M209Config {
    pins: [PinPattern; WHEEL_COUNT],
    positions: [WheelPosition; WHEEL_COUNT],
    bars: [DrumBar; DRUM_BAR_COUNT],
}

impl M209Config {
    /// Assemble a machine key from typed components, checking wheel identities.
    pub fn new(
        pins: [PinPattern; WHEEL_COUNT],
        positions: [WheelPosition; WHEEL_COUNT],
        bars: [DrumBar; DRUM_BAR_COUNT],
    ) -> Result<Self, KeyError> {
        // Reuse the existing wheel-bank validator rather than replicating it.
        WheelBank::new(pins, positions)?;

        Ok(Self { pins, positions, bars })
    }

    /// Parse effective-pin letters and the six visible wheel indicator letters.
    ///
    /// Letter validation uses each wheel's historical printed alphabet; it
    /// rejects unsupported letters rather than silently normalizing them.
    pub fn from_letters(
        pins: [&str; WHEEL_COUNT],
        indicators: &str,
        bars: [DrumBar; DRUM_BAR_COUNT],
    ) -> Result<Self, KeyError> {
        if indicators.len() != WHEEL_COUNT {
            return Err(KeyError::InvalidIndicatorLength(indicators.len()));
        }

        let mut patterns = core::array::from_fn(|index| {
            let wheel = WheelId::new(index as u8 + 1).expect("six valid wheel IDs");
            PinPattern::empty(wheel)
        });

        let mut positions = core::array::from_fn(|index| {
            let wheel = WheelId::new(index as u8 + 1).expect("six valid wheel IDs");
            WheelPosition::new(wheel, 0).expect("zero is a valid position")
        });

        for index in 0..WHEEL_COUNT {
            let wheel = WheelId::new(index as u8 + 1).expect("six valid wheel IDs");
            patterns[index] = PinPattern::from_letters(wheel, pins[index])?;
            positions[index] = wheel.position_for_letter(indicators.as_bytes()[index] as char)?;
        }

        Self::new(patterns, positions, bars)
    }

    pub const fn pins(&self) -> &[PinPattern; WHEEL_COUNT] {
        &self.pins
    }

    pub const fn positions(&self) -> &[WheelPosition; WHEEL_COUNT] {
        &self.positions
    }

    pub const fn bars(&self) -> &[DrumBar; DRUM_BAR_COUNT] {
        &self.bars
    }

    /// Build an independent frozen core at the specified initial positions.
    pub fn build_core(&self) -> M209Core {
        let wheels = WheelBank::new(self.pins, self.positions)
            .expect("configuration wheel identities were validated at construction");

        M209Core::new(wheels, LugDrum::new(self.bars))
    }

    /// Build an independent stateful machine, resetting to this key's positions.
    pub fn build_machine(&self) -> M209Machine {
        M209Machine::new(self.build_core())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{
        MANUAL_1944_CHECK, MANUAL_1944_PINS, PYTHON_REFERENCE_PINS,
        PYTHON_REFERENCE_START, manual_1944_drum, parse_pin_fixture,
        python_reference_drum,
    };
    use crate::Contact;

    #[test]
    fn manual_key_matches_the_historical_known_answer() {
        let config = M209Config::from_letters(
            MANUAL_1944_PINS,
            "AAAAAA",
            manual_1944_drum(),
        ).unwrap();
        let mut machine = config.build_machine();

        let ciphertext: String = (0..26)
            .map(|_| machine.convert_contact(Contact::A).letter())
            .collect();

        assert_eq!(ciphertext, MANUAL_1944_CHECK);
        assert_eq!(config.build_core().wheels().visible_letters(), "AAAAAA");
    }

    #[test]
    fn python_key_retains_all_twenty_seven_bars_and_positions() {
        let config = M209Config::from_letters(
            PYTHON_REFERENCE_PINS,
            PYTHON_REFERENCE_START,
            python_reference_drum(),
        ).unwrap();

        assert_eq!(config.bars().len(), DRUM_BAR_COUNT);
        assert_eq!(config.build_machine().core().wheels().visible_letters(), "FFEGJP");
    }

    #[test]
    fn wrong_wheel_order_is_rejected() {
        let mut pins = parse_pin_fixture(MANUAL_1944_PINS).unwrap();
        let positions = core::array::from_fn(|index| {
            WheelId::new(index as u8 + 1).unwrap().position_for_letter('A').unwrap()
        });

        pins.swap(0, 1);

        assert!(matches!(
            M209Config::new(pins, positions, manual_1944_drum()),
            Err(KeyError::WheelMismatch { .. })
        ));
    }

    #[test]
    fn indicators_reject_wrong_length_and_unprinted_letters() {
        assert_eq!(
            M209Config::from_letters(MANUAL_1944_PINS, "AAAAA", manual_1944_drum()),
            Err(KeyError::InvalidIndicatorLength(5))
        );

        assert!(matches!(
            M209Config::from_letters(MANUAL_1944_PINS, "AWAAAA", manual_1944_drum()),
            Err(KeyError::InvalidWheelLetter { .. })
        ));
    }

    #[test]
    fn separately_built_machines_do_not_share_mutable_state() {
        let config = M209Config::from_letters(
            MANUAL_1944_PINS,
            "AAAAAA",
            manual_1944_drum(),
        ).unwrap();

        let mut first = config.build_machine();
        let second = config.build_machine();

        first.convert_contact(Contact::A);

        assert_eq!(first.core().wheels().visible_letters(), "BBBBBB");
        assert_eq!(second.core().wheels().visible_letters(), "AAAAAA");
        assert_eq!(config.build_machine(), second);
    }
}
