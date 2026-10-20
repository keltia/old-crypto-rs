//! Fixed 25-bar SG-41 cage displacement, before print-head conversion.
//!
//! Wheels 1–5 contribute 1, 2, 4, 8, and 10 respectively. An active
//! sixth-wheel cage pin complements the first five pin states. The cage
//! pins are sensed at +8 *after* stepping phases I and II.

use super::types::PinSensor;
use super::wheel_bank::{PinSnapshot, WheelBank};

/// Fixed contributions of the first five SG-41 wheels (25 bars total).
pub const CAGE_WEIGHTS: [u8; 5] = [1, 2, 4, 8, 10];

/// The cage result and the six pin states from which it was calculated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Displacement {
    /// Cage pin states in physical wheel order, before sixth-wheel inversion.
    pub sensed_pins: PinSnapshot,
    /// True when wheel 6 complements the states of wheels 1–5.
    pub inverted: bool,
    /// Print-head advancement in the range 0..=25.
    pub steps: u8,
}

/// Convert one six-pin cage snapshot to the SG-41 displacement (0..=25).
///
/// The fixed five-wheel weighted sum is complemented when wheel 6 is active.
/// This does not advance the machine or transform a plaintext character.
pub fn displacement_from_pins(sensed_pins: PinSnapshot) -> Displacement {
    let pins = sensed_pins.bits();
    let inverted = pins[5];
    let steps = CAGE_WEIGHTS
        .iter()
        .zip(pins[..5].iter())
        .map(|(&weight, &active)| if active != inverted { weight } else { 0 })
        .sum();

    Displacement {
        sensed_pins,
        inverted,
        steps,
    }
}

/// Read the +8 cage sensor at the **current** wheel positions.
///
/// A full cipher cycle must call this after [`super::stepping::step_before_cipher`]
/// and before [`super::stepping::step_after_cipher`].
pub fn sense_displacement(bank: &WheelBank) -> Displacement {
    displacement_from_pins(bank.sense(PinSensor::Displacement))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PinPattern, WheelId, WheelPosition, WHEEL_COUNT, step_before_cipher};

    const PINS: [&str; WHEEL_COUNT] = [
        "0001101011000100010001101",
        "0110100100001011100101100",
        "11001001000100100100010",
        "01001000111010001110010",
        "001001001010000101011010",
        "011001100110001011010100",
    ];

    fn reference_bank() -> WheelBank {
        let positions = std::array::from_fn(|i| {
            WheelPosition::new(WheelId::new(i as u8 + 1).unwrap(), [0, 1, 2, 3, 0, 0][i])
                .unwrap()
        });
        let pins = std::array::from_fn(|i| {
            PinPattern::from_table_bits(WheelId::new(i as u8 + 1).unwrap(), PINS[i]).unwrap()
        });

        WheelBank::new(positions, pins).unwrap()
    }

    #[test]
    fn published_cage_examples() {
        // Figure 16, page 19: 100110 -> 19; 100111 -> 6; 100100 -> 9.
        assert_eq!(displacement_from_pins(PinSnapshot::from_bits([true, false, false, true, true, false])).steps, 19);
        assert_eq!(displacement_from_pins(PinSnapshot::from_bits([true, false, false, true, true, true])).steps, 6);
        assert_eq!(displacement_from_pins(PinSnapshot::from_bits([true, false, false, true, false, false])).steps, 9);
    }

    #[test]
    fn inversion_complements_all_five_contributions() {
        for mask in 0u8..32 {
            let pins = std::array::from_fn(|i| i < 5 && (mask & (1 << i)) != 0);
            let direct = displacement_from_pins(PinSnapshot::from_bits(pins));
            let inverted = displacement_from_pins(PinSnapshot::from_bits([pins[0], pins[1], pins[2], pins[3], pins[4], true]));

            assert!(!direct.inverted);
            assert!(inverted.inverted);
            assert_eq!(direct.steps + inverted.steps, 25);
            assert!(direct.steps <= 25);
            assert!(inverted.steps <= 25);
        }
    }

    #[test]
    fn reads_post_phase_two_snapshot_without_stepping() {
        let mut bank = reference_bank();
        let before = bank.sense(PinSensor::Displacement);
        assert_eq!(before.bits(), [true, false, false, false, true, false]);

        let pre_cipher = step_before_cipher(&mut bank);
        assert_eq!(pre_cipher.cipher_positions, bank.positions());
        let positions = bank.positions();
        let expected = displacement_from_pins(bank.sense(PinSensor::Displacement));
        let actual = sense_displacement(&bank);

        assert_eq!(actual, expected);
        assert_eq!(actual.sensed_pins.bits(), [true, false, false, true, true, true]);
        assert_eq!(actual.steps, 6);
        assert_eq!(bank.positions(), positions);
        // Ensures the cage reading is not taken from the initial windows.
        assert_ne!(actual.sensed_pins, before);
    }
}
