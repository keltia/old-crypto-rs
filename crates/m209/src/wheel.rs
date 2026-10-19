//! Six pin wheels, their displayed positions, and the mechanically sensed pins.
//!
//! The position marked in the indicator window is *not* the pin touching the
//! guide arm. In the historical M-209 configuration, windows `AAAAAA` sense
//! `PONMLK`, respectively (TM 11-380 worked example).

use crate::{KeyError, PinPattern, WHEEL_COUNT, WheelId, WheelPosition};

/// Number of letter positions from the indicator to the guide-arm pin,
/// in physical wheel order. For `A`, these are `P O N M L K`.
const SENSING_OFFSETS: [u8; WHEEL_COUNT] = [15, 14, 13, 12, 11, 10];

/// A single mounted wheel with fixed pins and a mutable visible position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinWheel {
    pins: PinPattern,
    position: WheelPosition,
}

impl PinWheel {
    /// Build a wheel, rejecting accidental mismatches of physical identity.
    pub fn new(pins: PinPattern, position: WheelPosition) -> Result<Self, KeyError> {
        if pins.wheel() != position.wheel() {
            return Err(KeyError::WheelMismatch {
                expected: pins.wheel(),
                actual: position.wheel(),
            });
        }

        Ok(Self { pins, position })
    }

    pub const fn wheel(&self) -> WheelId {
        self.position.wheel()
    }

    pub const fn position(&self) -> WheelPosition {
        self.position
    }

    /// The *printed* letter next to the indicator window.
    pub fn visible_letter(&self) -> char {
        self.position.letter()
    }

    /// Pin index physically sensed at the guide arm, not the window index.
    pub fn sensed_position(&self) -> WheelPosition {
        let wheel = self.wheel();
        let offset = SENSING_OFFSETS[wheel.array_index()];
        let index = (self.position.index() + offset) % wheel.size();

        WheelPosition::new(wheel, index).expect("offset is reduced modulo wheel size")
    }

    pub fn sensed_letter(&self) -> char {
        self.sensed_position().letter()
    }

    pub fn is_effective(&self) -> bool {
        self.pins.is_effective(self.sensed_position())
            .expect("pin pattern belongs to its wheel")
    }

    /// Advance one position after processing a machine character.
    pub fn advance(&mut self) {
        self.position = self.position.advance();
    }

    pub fn set_position(&mut self, position: WheelPosition) -> Result<(), KeyError> {
        if position.wheel() != self.wheel() {
            return Err(KeyError::WheelMismatch {
                expected: self.wheel(),
                actual: position.wheel(),
            });
        }

        self.position = position;
        Ok(())
    }
}

/// The six wheels, maintained in physical wheel order (1 through 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WheelBank {
    wheels: [PinWheel; WHEEL_COUNT],
}

impl WheelBank {
    pub fn new(
        patterns: [PinPattern; WHEEL_COUNT],
        positions: [WheelPosition; WHEEL_COUNT],
    ) -> Result<Self, KeyError> {
        for index in 0..WHEEL_COUNT {
            let expected = WheelId::new(index as u8 + 1).expect("six valid physical wheel IDs");

            if patterns[index].wheel() != expected {
                return Err(KeyError::WheelMismatch {
                    expected,
                    actual: patterns[index].wheel(),
                });
            }

            if positions[index].wheel() != expected {
                return Err(KeyError::WheelMismatch {
                    expected,
                    actual: positions[index].wheel(),
                });
            }
        }

        let wheels = core::array::from_fn(|index| {
            PinWheel::new(patterns[index], positions[index])
                .expect("wheel identity was validated above")
        });

        Ok(Self { wheels })
    }

    pub fn wheels(&self) -> &[PinWheel; WHEEL_COUNT] {
        &self.wheels
    }

    pub fn positions(&self) -> [WheelPosition; WHEEL_COUNT] {
        self.wheels.map(|wheel| wheel.position())
    }

    pub fn visible_letters(&self) -> String {
        self.wheels.iter().map(PinWheel::visible_letter).collect()
    }

    pub fn sensed_letters(&self) -> String {
        self.wheels.iter().map(PinWheel::sensed_letter).collect()
    }

    /// Bit 0 is wheel 1, bit 5 wheel 6; neutral positions are not represented.
    pub fn effective_mask(&self) -> u8 {
        self.wheels.iter().enumerate().fold(0_u8, |mask, (i, wheel)| {
            mask | (u8::from(wheel.is_effective()) << i)
        })
    }

    /// The six independent wheels all advance exactly once per character.
    pub fn advance(&mut self) {
        for wheel in &mut self.wheels {
            wheel.advance();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{MANUAL_1944_PINS, parse_pin_fixture};

    fn manual_bank() -> WheelBank {
        let patterns = parse_pin_fixture(MANUAL_1944_PINS).unwrap();
        let positions = core::array::from_fn(|i| {
            let wheel = WheelId::new(i as u8 + 1).unwrap();
            wheel.position_for_letter('A').unwrap()
        });

        WheelBank::new(patterns, positions).unwrap()
    }

    #[test]
    fn historical_window_and_pin_offset() {
        let mut bank = manual_bank();
        assert_eq!(bank.visible_letters(), "AAAAAA");
        assert_eq!(bank.sensed_letters(), "PONMLK");

        bank.advance();
        assert_eq!(bank.visible_letters(), "BBBBBB");
        assert_eq!(bank.sensed_letters(), "QPONML");
    }

    #[test]
    fn historical_first_character_effective_wheels_are_2_3_4_6() {
        let bank = manual_bank();
        assert_eq!(bank.effective_mask(), 0b10_1110);
    }

    #[test]
    fn all_wheels_wrap_independently() {
        let bank = manual_bank();
        let initial = bank.positions();

        for wheel in bank.wheels().iter().copied() {
            let mut wheel = wheel;
            let initial = wheel.position();
            for _ in 0..wheel.wheel().size() {
                wheel.advance();
            }
            assert_eq!(wheel.position(), initial);
        }
        assert_eq!(bank.positions(), initial);
    }

    #[test]
    fn wheel_and_bank_reject_mismatched_identities() {
        let wheel1 = WheelId::new(1).unwrap();
        let wheel2 = WheelId::new(2).unwrap();
        let p1 = PinPattern::empty(wheel1);
        let pos2 = wheel2.position_for_letter('A').unwrap();
        assert!(matches!(PinWheel::new(p1, pos2), Err(KeyError::WheelMismatch { .. })));

        let mut bank = manual_bank();
        assert!(matches!(bank.wheels[0].set_position(pos2), Err(KeyError::WheelMismatch { .. })));
        let mut patterns = parse_pin_fixture(MANUAL_1944_PINS).unwrap();
        patterns.swap(0, 1);
        assert!(matches!(WheelBank::new(patterns, bank.positions()), Err(KeyError::WheelMismatch { .. })));
    }

    #[test]
    fn effective_pin_tracks_physical_pin_after_advance() {
        let mut bank = manual_bank();
        for _ in 0..30 {
            for wheel in bank.wheels() {
                let sensed = wheel.sensed_position();
                assert_eq!(wheel.is_effective(), wheel.pins.is_effective(sensed).unwrap());
            }
            bank.advance();
        }
    }
}
