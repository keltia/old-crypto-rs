//! Four-phase crank-driven stepping for the alphabetic SG-41.
//!
//! A complete turn consists of two phases before encipherment and two after.
//! The first stepping-pin snapshot is latched for phases I and II. The second
//! is sampled only after the cipher action, immediately before phase III.
//! All phase decisions are simultaneous within each phase (Table 4).

use super::types::{PinSensor, WHEEL_COUNT, WheelPosition};
use super::wheel_bank::{PinSnapshot, WheelBank};

/// Information retained between the pre- and post-cipher stages of a crank turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreCipherStep {
    /// Stepping pins sampled before phase I (also used by phase II).
    pub first_latch: PinSnapshot,
    /// Wheels advanced in phase I.
    pub phase_one: [bool; WHEEL_COUNT],
    /// Wheels advanced in phase II.
    pub phase_two: [bool; WHEEL_COUNT],
    /// Wheel positions at the moment the cipher mechanism operates.
    pub cipher_positions: [WheelPosition; WHEEL_COUNT],
}

/// A complete stepping trace for one crank revolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SteppingTrace {
    pub before_cipher: PreCipherStep,
    /// Stepping pins resampled after encipherment, before phase III.
    pub second_latch: PinSnapshot,
    pub phase_three: [bool; WHEEL_COUNT],
    pub phase_four: [bool; WHEEL_COUNT],
    pub final_positions: [WheelPosition; WHEEL_COUNT],
}

/// Apply phases I and II, in that order, before deriving the cipher output.
///
/// Phase I steps wheel `n + 1` for each active wheel-`n` pin (1–5), but only
/// when the *original* wheel-6 stepping pin is active. Phase II advances all
/// six wheels iff that same original wheel-6 pin was active. Wheel 6 moving
/// during phase I must **not** change the decision for phase II.
pub fn step_before_cipher(bank: &mut WheelBank) -> PreCipherStep {
    let first_latch = bank.sense(PinSensor::Stepping);
    let active = first_latch.bits();
    let mut phase_one = [false; WHEEL_COUNT];
    let phase_two = [active[5]; WHEEL_COUNT];

    if active[5] {
        phase_one[1..].copy_from_slice(&active[..5]);
    }

    bank.advance_mask(phase_one);
    bank.advance_mask(phase_two);

    PreCipherStep {
        first_latch,
        phase_one,
        phase_two,
        cipher_positions: bank.positions(),
    }
}

/// Apply phases III and IV after deriving the cipher output.
///
/// Phase III reads a **new** stepping-pin snapshot from the updated wheels;
/// wheel 6 does not gate this phase. Phase IV always advances all six wheels.
pub fn step_after_cipher(bank: &mut WheelBank, before_cipher: PreCipherStep) -> SteppingTrace {
    let second_latch = bank.sense(PinSensor::Stepping);
    let active = second_latch.bits();
    let mut phase_three = [false; WHEEL_COUNT];
    phase_three[1..].copy_from_slice(&active[..5]);
    let phase_four = [true; WHEEL_COUNT];

    bank.advance_mask(phase_three);
    bank.advance_mask(phase_four);

    SteppingTrace {
        before_cipher,
        second_latch,
        phase_three,
        phase_four,
        final_positions: bank.positions(),
    }
}

/// Execute one full crank revolution without performing encryption.
///
/// Used for wheel-only simulations. A future cipher implementation should
/// instead call [`step_before_cipher`], calculate the output from the resulting
/// wheel state, then call [`step_after_cipher`].
pub fn step_crank(bank: &mut WheelBank) -> SteppingTrace {
    let before_cipher = step_before_cipher(bank);
    step_after_cipher(bank, before_cipher)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PinPattern, WheelId, WheelPosition};

    const PINS: [&str; 6] = [
        "0001101011000100010001101",
        "0110100100001011100101100",
        "11001001000100100100010",
        "01001000111010001110010",
        "001001001010000101011010",
        "011001100110001011010100",
    ];

    fn bank() -> WheelBank {
        let positions = std::array::from_fn(|i| {
            WheelPosition::new(WheelId::new(i as u8 + 1).unwrap(), [0, 1, 2, 3, 0, 0][i]).unwrap()
        });
        let pins = std::array::from_fn(|i| {
            PinPattern::from_table_bits(WheelId::new(i as u8 + 1).unwrap(), PINS[i]).unwrap()
        });
        WheelBank::new(positions, pins).unwrap()
    }

    #[test]
    fn first_two_phases_share_original_latch() {
        let mut wheels = bank();
        let initial = wheels.sense(PinSensor::Stepping);
        let pre = step_before_cipher(&mut wheels);

        assert_eq!(pre.first_latch, initial);
        assert_eq!(pre.phase_one, [false, false, true, false, true, true]);
        assert_eq!(pre.phase_two, [true; WHEEL_COUNT]);
        assert_eq!(pre.cipher_positions, wheels.positions());
    }

    #[test]
    fn post_cipher_phase_resenses_and_final_phase_always_advances() {
        let mut wheels = bank();
        let pre = step_before_cipher(&mut wheels);
        let refreshed = wheels.sense(PinSensor::Stepping);
        let trace = step_after_cipher(&mut wheels, pre);

        assert_eq!(trace.second_latch, refreshed);
        assert_eq!(trace.phase_three[0], false);
        assert_eq!(&trace.phase_three[1..], &refreshed.bits()[..5]);
        assert_eq!(trace.phase_four, [true; WHEEL_COUNT]);
        assert_eq!(trace.final_positions, wheels.positions());
    }

    #[test]
    fn split_and_whole_crank_produce_identical_results() {
        let mut single = bank();
        let mut split = bank();
        for _ in 0..100 {
            let expected = step_crank(&mut single);
            let first = step_before_cipher(&mut split);
            let actual = step_after_cipher(&mut split, first);
            assert_eq!(actual, expected);
            assert_eq!(single.positions(), split.positions());
        }
    }
}
