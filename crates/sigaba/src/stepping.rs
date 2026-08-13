//! Fixed CSP-889 index-output to cipher-step pairing.
//!
//! The ten index-bank outputs are ORed in five fixed pairs:
//!
//! ```text
//! outputs 0 or 9 -> cipher slot 0
//! outputs 7 or 8 -> cipher slot 1
//! outputs 5 or 6 -> cipher slot 2
//! outputs 3 or 4 -> cipher slot 3
//! outputs 1 or 2 -> cipher slot 4
//! ```
//!
//! If both outputs in a pair are active, the cipher rotor still steps only
//! once.

use super::control::IndexSignals;

/// Index-output pairs driving cipher slots from left to right.
const INDEX_OUTPUT_PAIR_MASKS: [u16; 5] = [
    (1 << 0) | (1 << 9),
    (1 << 7) | (1 << 8),
    (1 << 5) | (1 << 6),
    (1 << 3) | (1 << 4),
    (1 << 1) | (1 << 2),
];

/// Set of cipher rotors selected to step for one keypress.
///
/// Only the low five bits are used, one per cipher slot from left to right.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct CipherStepSet(u8);

impl CipherStepSet {
    const MASK: u8 = 0x1f;

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn empty() -> Self {
        Self(0)
    }

    #[must_use]
    pub(crate) const fn from_bits(bits: u8) -> Self {
        Self(bits & Self::MASK)
    }

    #[must_use]
    pub(crate) const fn bits(self) -> u8 {
        self.0
    }

    #[must_use]
    pub(crate) const fn contains_slot(self, slot: usize) -> bool {
        slot < 5 && (self.0 & (1_u8 << slot) != 0)
    }

    #[cfg(test)]
    pub(crate) fn insert_slot(&mut self, slot: usize) {
        assert!(slot < 5, "SIGABA cipher slot must be in 0..5");
        self.0 |= 1_u8 << slot;
    }

    #[must_use]
    pub(crate) const fn count(self) -> u32 {
        self.0.count_ones()
    }
}

/// Return the cipher slot driven by one active index output.
#[cfg(test)]
#[must_use]
pub(crate) fn index_output_to_cipher_slot(output: crate::contact::Contact10) -> usize {
    match output.get() {
        0 | 9 => 0,
        7 | 8 => 1,
        5 | 6 => 2,
        3 | 4 => 3,
        1 | 2 => 4,
        _ => unreachable!("Contact10 is always in 0..10"),
    }
}

/// Convert active index outputs into the set of cipher rotors to step.
#[must_use]
pub(crate) fn cipher_steps_from_index_outputs(outputs: IndexSignals) -> CipherStepSet {
    let output_bits = outputs.bits();
    let step_bits = INDEX_OUTPUT_PAIR_MASKS
        .into_iter()
        .enumerate()
        .fold(0_u8, |steps, (slot, pair)| {
            steps | (u8::from(output_bits & pair != 0) << slot)
        });

    CipherStepSet::from_bits(step_bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact::Contact10;

    fn c10(value: u8) -> Contact10 {
        Contact10::new(value).unwrap()
    }

    #[test]
    fn published_csp889_pairing_is_exact() {
        let expected = [
            (0, 0), (9, 0),
            (7, 1), (8, 1),
            (5, 2), (6, 2),
            (3, 3), (4, 3),
            (1, 4), (2, 4),
        ];

        for (output, slot) in expected {
            assert_eq!(index_output_to_cipher_slot(c10(output)), slot);
        }
    }

    #[test]
    fn both_outputs_of_a_pair_step_only_once() {
        let outputs = IndexSignals::from_bits((1_u16 << 0) | (1_u16 << 9));
        let steps = cipher_steps_from_index_outputs(outputs);

        assert_eq!(steps.count(), 1);
        assert!(steps.contains_slot(0));
        assert_eq!(steps.bits(), 0b00001);
    }

    #[test]
    fn one_output_from_every_pair_steps_all_five_rotors() {
        let outputs = IndexSignals::from_bits(
            (1_u16 << 0)
                | (1_u16 << 7)
                | (1_u16 << 5)
                | (1_u16 << 3)
                | (1_u16 << 1),
        );
        let steps = cipher_steps_from_index_outputs(outputs);

        assert_eq!(steps.count(), 5);
        assert_eq!(steps.bits(), 0b11111);
    }

    #[test]
    fn realistic_one_to_four_index_outputs_select_one_to_four_slots() {
        let outputs = IndexSignals::from_bits(
            (1_u16 << 9) | (1_u16 << 8) | (1_u16 << 4) | (1_u16 << 2),
        );
        let steps = cipher_steps_from_index_outputs(outputs);

        assert_eq!(steps.count(), 4);
        assert!(steps.contains_slot(0));
        assert!(steps.contains_slot(1));
        assert!(steps.contains_slot(3));
        assert!(steps.contains_slot(4));
        assert!(!steps.contains_slot(2));
    }

    #[test]
    fn cipher_step_set_masks_nonexistent_slots() {
        assert_eq!(CipherStepSet::from_bits(u8::MAX).bits(), 0x1f);
    }

    #[test]
    fn direct_pair_collapse_matches_contact_mapping_for_every_signal_set() {
        for output_bits in 0..=0x03ff_u16 {
            let steps = cipher_steps_from_index_outputs(IndexSignals::from_bits(output_bits));
            let mut expected = CipherStepSet::empty();

            for output in 0..10_u8 {
                if output_bits & (1_u16 << output) != 0 {
                    expected.insert_slot(index_output_to_cipher_slot(c10(output)));
                }
            }

            assert_eq!(steps, expected, "index output bits {output_bits:010b}");
        }
    }
}
