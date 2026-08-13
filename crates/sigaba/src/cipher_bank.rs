//! SIGABA five-rotor cipher bank.
//!
//! Physical slots are stored left-to-right as indices `0..4`.
//!
//! The Pekelney ECM Mark II reference model uses:
//!
//! ```text
//! encipher: slots 0 -> 4 using AlphabetRotor::forward()
//! decipher: slots 4 -> 0 using AlphabetRotor::reverse()
//! ```
//!
//! This module also applies a precomputed `CipherStepSet` to the selected
//! mounted cipher rotors. It does not decide *when* in the per-character cycle
//! stepping occurs; Step 12 will compose that timing with the stepping maze.

use super::{
    alphabet_rotor::AlphabetRotor,
    contact::Contact26,
    rotor_set::{MountedRotorTransforms, RotorSet},
    stepping::CipherStepSet,
};

/// Five mounted SIGABA cipher rotors in physical left-to-right slot order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CipherBank {
    rotors: [AlphabetRotor; 5],
}

impl CipherBank {
    #[must_use]
    pub(crate) const fn new(rotors: [AlphabetRotor; 5]) -> Self {
        Self { rotors }
    }

    /// Encipher one electrical contact through the alphabet maze.
    #[must_use]
    pub(crate) fn encipher_with(
        &self,
        transforms: &[&MountedRotorTransforms; 5],
        mut input: Contact26,
    ) -> Contact26 {
        for (rotor, &transform) in self.rotors.iter().zip(transforms) {
            input = rotor.forward_with(transform, input);
        }
        input
    }

    /// Decipher one electrical contact through the inverse alphabet-maze path.
    #[must_use]
    pub(crate) fn decipher_with(
        &self,
        transforms: &[&MountedRotorTransforms; 5],
        mut input: Contact26,
    ) -> Contact26 {
        for (rotor, &transform) in self.rotors.iter().zip(transforms).rev() {
            input = rotor.reverse_with(transform, input);
        }
        input
    }

    pub(crate) fn resolve<'a>(
        &self,
        rotor_set: &'a RotorSet,
    ) -> [&'a MountedRotorTransforms; 5] {
        self.rotors.map(|rotor| rotor.resolve(rotor_set))
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn encipher(&self, input: Contact26) -> Contact26 {
        let transforms = self.resolve(super::data::reference_rotor_set().unwrap());
        self.encipher_with(&transforms, input)
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn decipher(&self, input: Contact26) -> Contact26 {
        let transforms = self.resolve(super::data::reference_rotor_set().unwrap());
        self.decipher_with(&transforms, input)
    }

    /// Step exactly the cipher rotors selected by `steps`.
    ///
    /// Each selected mounted rotor moves once according to its physical
    /// orientation. A rotor cannot double-step because `CipherStepSet` is a
    /// set, not a list of energized index outputs.
    pub(crate) fn apply_steps(&mut self, steps: CipherStepSet) {
        for slot in 0..5 {
            if steps.contains_slot(slot) {
                self.rotors[slot].step();
            }
        }
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn rotor(&self, slot: usize) -> &AlphabetRotor {
        &self.rotors[slot]
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn positions(&self) -> [u8; 5] {
        self.rotors.map(|rotor| rotor.position().get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        alphabet_rotor::Orientation,
        contact::Position26,
        data::{LargeRotorId, LargeRotorSet},
    };

    fn rotor(id: u8, position: u8, orientation: Orientation) -> AlphabetRotor {
        AlphabetRotor::from_reference(
            LargeRotorSet::PekelneyReference,
            LargeRotorId::new(id).unwrap(),
            Position26::new(position).unwrap(),
            orientation,
        )
        .unwrap()
    }

    fn contact(value: u8) -> Contact26 {
        Contact26::new(value).unwrap()
    }

    fn bank() -> CipherBank {
        CipherBank::new([
            rotor(0, 0, Orientation::Normal),
            rotor(1, 1, Orientation::Reversed),
            rotor(2, 14, Orientation::Normal),
            rotor(3, 25, Orientation::Reversed),
            rotor(4, 4, Orientation::Normal),
        ])
    }

    #[test]
    fn encipher_traversal_is_left_to_right_using_forward_direction() {
        let bank = bank();

        for input in 0..26 {
            let mut expected = contact(input);
            for slot in 0..5 {
                expected = bank.rotor(slot).forward(expected);
            }

            assert_eq!(bank.encipher(contact(input)), expected);
        }
    }

    #[test]
    fn decipher_traversal_is_right_to_left_using_reverse_direction() {
        let bank = bank();

        for input in 0..26 {
            let mut expected = contact(input);
            for slot in (0..5).rev() {
                expected = bank.rotor(slot).reverse(expected);
            }

            assert_eq!(bank.decipher(contact(input)), expected);
        }
    }

    #[test]
    fn encipher_and_decipher_are_exhaustive_inverses() {
        for a in 0..3 {
            for b in 0..3 {
                let bank = CipherBank::new([
                    rotor(0, a, Orientation::Normal),
                    rotor(1, b, Orientation::Reversed),
                    rotor(2, (a + b + 5) % 26, Orientation::Normal),
                    rotor(3, (2 * a + b + 7) % 26, Orientation::Reversed),
                    rotor(4, (a + 2 * b + 11) % 26, Orientation::Normal),
                ]);

                for input in 0..26 {
                    let input = contact(input);
                    assert_eq!(bank.decipher(bank.encipher(input)), input);
                    assert_eq!(bank.encipher(bank.decipher(input)), input);
                }
            }
        }
    }

    #[test]
    fn selected_cipher_rotors_step_once_and_only_once() {
        let mut bank = CipherBank::new([
            rotor(0, 0, Orientation::Normal),
            rotor(1, 0, Orientation::Normal),
            rotor(2, 0, Orientation::Normal),
            rotor(3, 0, Orientation::Normal),
            rotor(4, 0, Orientation::Normal),
        ]);

        let steps = CipherStepSet::from_bits(0b01101);
        bank.apply_steps(steps);

        assert_eq!(bank.positions(), [25, 0, 25, 25, 0]);
    }

    #[test]
    fn stepping_respects_each_rotors_orientation() {
        let mut bank = CipherBank::new([
            rotor(0, 14, Orientation::Normal),
            rotor(1, 14, Orientation::Reversed),
            rotor(2, 14, Orientation::Normal),
            rotor(3, 14, Orientation::Reversed),
            rotor(4, 14, Orientation::Normal),
        ]);

        bank.apply_steps(CipherStepSet::from_bits(0b11111));

        assert_eq!(
            bank.positions(),
            [
                13, // O -> N normal
                15, // O -> P reversed
                13,
                15,
                13,
            ],
        );
    }

    #[test]
    fn empty_step_set_leaves_cipher_bank_unchanged() {
        let mut bank = bank();
        let before = bank;

        bank.apply_steps(CipherStepSet::empty());

        assert_eq!(bank, before);
    }

    #[test]
    fn both_members_of_index_pair_cannot_double_step_here() {
        // The paired-output collapse was tested in Step 7. This bank sees only
        // the resulting set bit, so repeated application within one decision is
        // impossible.
        let mut bank = CipherBank::new([
            rotor(0, 0, Orientation::Normal),
            rotor(1, 0, Orientation::Normal),
            rotor(2, 0, Orientation::Normal),
            rotor(3, 0, Orientation::Normal),
            rotor(4, 0, Orientation::Normal),
        ]);

        let steps = CipherStepSet::from_bits(1 << 2);
        bank.apply_steps(steps);

        assert_eq!(bank.positions(), [0, 0, 25, 0, 0]);
    }

    #[test]
    fn fixed_pekelney_reference_fixture_is_stable() {
        let bank = CipherBank::new([
            rotor(0, 0, Orientation::Normal),
            rotor(1, 0, Orientation::Normal),
            rotor(2, 0, Orientation::Normal),
            rotor(3, 0, Orientation::Normal),
            rotor(4, 0, Orientation::Normal),
        ]);

        let output: String = (0..26)
            .map(|value| char::from(b'A' + bank.encipher(contact(value)).get()))
            .collect();

        // Frozen composition fixture for reference rotors 0..4 at AAAAA.
        assert_eq!(output, "XUODFRKSMQPZYBCAIGVNWTELJH");
    }
}
