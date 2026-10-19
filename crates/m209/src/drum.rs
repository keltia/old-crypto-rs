//! M-209 lug-drum engagement and variable-toothed-gear displacement.
//!
//! Each of the 27 bars carries two lugs. A bar engages if **either** lug
//! addresses an effective pin wheel, and contributes exactly one tooth even
//! when both lugs are effective. The two neutral (zero) positions never engage.
//!
//! Source: US War Department, TM 11-380 (17 March 1944), paragraph 8d,
//! Table II (printed p. 15); worked example described at
//! https://en.wikipedia.org/wiki/M-209#Example_encoding .

use crate::{DRUM_BAR_COUNT, DrumBar};

/// Mask of effective guide arms: bit 0 is wheel 1; bit 5 is wheel 6.
const WHEEL_MASK: u8 = 0b00_111111;

/// The complete adjustable lug drum, with bars stored in physical order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LugDrum {
    bars: [DrumBar; DRUM_BAR_COUNT],
}

impl LugDrum {
    /// Construct a drum from exactly 27 typed, ordered lug pairs.
    ///
    /// Structural validation (six valid wheel numbers or neutral) is already
    /// enforced by `Lug`; historical key-list policies are a later concern.
    pub const fn new(bars: [DrumBar; DRUM_BAR_COUNT]) -> Self {
        Self { bars }
    }

    pub const fn bars(&self) -> &[DrumBar; DRUM_BAR_COUNT] {
        &self.bars
    }

    /// Whether one physical bar moves sideways for the given guide-arm mask.
    pub fn bar_engages(bar: DrumBar, effective_wheels: u8) -> bool {
        let active = effective_wheels & WHEEL_MASK;

        [bar.left(), bar.right()].into_iter().any(|lug| {
            let number = lug.value();
            number != 0 && (active & (1_u8 << (number - 1))) != 0
        })
    }

    /// Engaged physical bars as a 27-bit bitset (bit 0 = bar 1).
    pub fn engaged_bar_mask(&self, effective_wheels: u8) -> u32 {
        let mut mask = 0_u32;

        for (index, &bar) in self.bars.iter().enumerate() {
            if Self::bar_engages(bar, effective_wheels) {
                mask |= 1_u32 << index;
            }
        }

        mask
    }

    /// Number of engaged bars, i.e. the mechanical displacement (0..=27).
    ///
    /// Do not reduce this value modulo 26 here: the drum models the actual
    /// number of teeth, not the later reciprocal alphabet transformation.
    pub fn displacement(&self, effective_wheels: u8) -> u8 {
        self.engaged_bar_mask(effective_wheels).count_ones() as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::manual_1944_drum;

    const fn lug(number: u8) -> crate::Lug {
        match crate::Lug::new(number) {
            Some(lug) => lug,
            None => panic!("invalid test lug"),
        }
    }

    #[test]
    fn both_lugs_engaged_still_move_only_one_bar() {
        let bar = DrumBar::new(lug(2), lug(6));

        assert!(LugDrum::bar_engages(bar, 0b10_0010));
        assert!(LugDrum::bar_engages(bar, 0b00_0010));
        assert!(LugDrum::bar_engages(bar, 0b10_0000));
        assert!(!LugDrum::bar_engages(bar, 0b00_0100));
    }

    #[test]
    fn neutral_lugs_do_not_engage() {
        let bar = DrumBar::new(lug(0), lug(0));

        for mask in 0..=63 {
            assert!(!LugDrum::bar_engages(bar, mask));
        }
    }

    #[test]
    fn historical_first_27_bar_engagement_matches_worked_example() {
        let drum = LugDrum::new(manual_1944_drum());
        let effective_wheels = 0b10_1110; // physical wheels 2, 3, 4 and 6

        let expected = (1..=3).chain(5..=21).fold(0_u32, |mask, number| {
            mask | (1_u32 << (number - 1))
        });

        assert_eq!(drum.engaged_bar_mask(effective_wheels), expected);
        assert_eq!(drum.displacement(effective_wheels), 20);
    }

    #[test]
    fn no_effective_wheels_produce_zero_displacement() {
        let drum = LugDrum::new(manual_1944_drum());

        assert_eq!(drum.engaged_bar_mask(0), 0);
        assert_eq!(drum.displacement(0), 0);
    }

    #[test]
    fn all_effective_wheels_engage_every_non_neutral_bar() {
        let drum = LugDrum::new(manual_1944_drum());

        assert_eq!(drum.displacement(0b11_1111), 27);
        assert_eq!(drum.engaged_bar_mask(0b11_1111), (1_u32 << 27) - 1);
    }

    #[test]
    fn displacement_never_exceeds_27_and_mask_ignores_unused_bits() {
        let drum = LugDrum::new(manual_1944_drum());

        for mask in 0..=63 {
            assert!(drum.displacement(mask) <= 27);
            assert_eq!(drum.displacement(mask), drum.displacement(mask | 0b1100_0000));
            assert_eq!(drum.engaged_bar_mask(mask), drum.engaged_bar_mask(mask | 0b1100_0000));
        }
    }
}
