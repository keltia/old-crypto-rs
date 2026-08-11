//! Fixed-position CSP-889 control rotor bank.
//!
//! The control bank consists of five 26-contact rotors stored in physical
//! left-to-right slot order. For each processed character the machine
//! simultaneously energizes control contacts F, G, H and I at the **right**
//! side of the bank. The signals travel right-to-left through all five control
//! rotors.
//!
//! With the `AlphabetRotor` direction convention established in Steps 4-5,
//! this physical right-to-left path uses `AlphabetRotor::reverse()` while
//! traversing slots `4 -> 0`.
//!
//! The resulting four letters are then passed through the fixed CSP-889
//! control-to-index OR banding from `control.rs`.
//!
//! This step deliberately keeps all five control rotors stationary. Metering
//! of slots 3/4/2 (fast/medium/slow) is added separately in Step 9.
//!
//! References:
//! - Stamp & Chan, *SIGABA: Cryptanalysis of the Full Keyspace*, §2:
//!   F/G/H/I are simultaneously applied to the rightmost control rotor and
//!   the control signal passes right-to-left.
//! - Pekelney-derived ECM Mark II simulator: `control_path()` traverses control
//!   rotor slots 4..0 using the inverse/decrypt electrical direction.

use super::{
    alphabet_rotor::AlphabetRotor,
    contact::Contact26,
    control::{band_control_outputs, IndexSignals},
};

/// The four fixed CSP-889 control-bank input contacts F, G, H and I.
pub(crate) const CONTROL_INPUTS: [Contact26; 4] = [
    contact_const(5), // F
    contact_const(6), // G
    contact_const(7), // H
    contact_const(8), // I
];

const fn contact_const(value: u8) -> Contact26 {
    match Contact26::new(value) {
        Some(contact) => contact,
        None => panic!("fixed SIGABA control input is out of range"),
    }
}

/// Five mounted control rotors in physical left-to-right slot order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControlBank {
    rotors: [AlphabetRotor; 5],
}

impl ControlBank {
    /// Construct a fixed-position control bank.
    #[must_use]
    pub(crate) const fn new(rotors: [AlphabetRotor; 5]) -> Self {
        Self { rotors }
    }

    /// Traverse one electrical contact from the right side of the bank to the
    /// left side.
    ///
    /// Physical slot storage is left-to-right, hence the iteration order
    /// `4 -> 0`. The signal enters each rotor in its inverse electrical
    /// direction.
    #[must_use]
    pub(crate) fn right_to_left(&self, mut input: Contact26) -> Contact26 {
        for rotor in self.rotors.iter().rev() {
            input = rotor.reverse(input);
        }
        input
    }

    /// Process the four simultaneous CSP-889 inputs F/G/H/I.
    #[must_use]
    pub(crate) fn outputs(&self) -> [Contact26; 4] {
        CONTROL_INPUTS.map(|input| self.right_to_left(input))
    }

    /// Process F/G/H/I and apply the fixed control-output OR banding to produce
    /// the active index-bank inputs.
    #[must_use]
    pub(crate) fn index_inputs(&self) -> IndexSignals {
        band_control_outputs(self.outputs())
    }

    /// Access one physical left-to-right control slot.
    #[must_use]
    pub(crate) const fn rotor(&self, slot: usize) -> &AlphabetRotor {
        &self.rotors[slot]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigaba::{
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

    fn letter(contact: Contact26) -> char {
        char::from(b'A' + contact.get())
    }

    #[test]
    fn fixed_control_inputs_are_exactly_f_g_h_i() {
        assert_eq!(
            CONTROL_INPUTS.map(letter),
            ['F', 'G', 'H', 'I'],
        );
    }

    #[test]
    fn bank_traverses_physical_slots_right_to_left_using_reverse_direction() {
        let bank = ControlBank::new([
            rotor(5, 0, Orientation::Normal),
            rotor(6, 0, Orientation::Normal),
            rotor(7, 0, Orientation::Normal),
            rotor(8, 0, Orientation::Normal),
            rotor(9, 0, Orientation::Normal),
        ]);

        for input in 0..26 {
            let mut expected = Contact26::new(input).unwrap();

            for slot in (0..5).rev() {
                expected = bank.rotor(slot).reverse(expected);
            }

            assert_eq!(
                bank.right_to_left(Contact26::new(input).unwrap()),
                expected,
            );
        }
    }

    #[test]
    fn pekelney_reference_control_fixture_at_a_is_j_c_r_a() {
        // Five reference rotors 5,6,7,8,9 from left to right, all normal at A.
        //
        // Independent composition of the published permutations gives:
        //   F -> J
        //   G -> C
        //   H -> R
        //   I -> A
        let bank = ControlBank::new([
            rotor(5, 0, Orientation::Normal),
            rotor(6, 0, Orientation::Normal),
            rotor(7, 0, Orientation::Normal),
            rotor(8, 0, Orientation::Normal),
            rotor(9, 0, Orientation::Normal),
        ]);

        assert_eq!(bank.outputs().map(letter), ['J', 'C', 'R', 'A']);
    }

    #[test]
    fn reference_fixture_bands_to_index_inputs_2_5_7_9() {
        // J -> 5, C -> 2, R -> 7, A -> 9.
        let bank = ControlBank::new([
            rotor(5, 0, Orientation::Normal),
            rotor(6, 0, Orientation::Normal),
            rotor(7, 0, Orientation::Normal),
            rotor(8, 0, Orientation::Normal),
            rotor(9, 0, Orientation::Normal),
        ]);

        let inputs = bank.index_inputs();

        assert_eq!(
            inputs.bits(),
            (1_u16 << 2) | (1_u16 << 5) | (1_u16 << 7) | (1_u16 << 9),
        );
        assert_eq!(inputs.count(), 4);
    }

    #[test]
    fn mixed_positions_and_orientations_have_frozen_control_fixture() {
        // Left-to-right:
        //   rotor 9 N @ A
        //   rotor 7 R @ B
        //   rotor 5 N @ O
        //   rotor 3 R @ Z
        //   rotor 1 N @ E
        //
        // Independent application of the Step-5 equations in physical
        // right-to-left order gives F/G/H/I -> Z/C/M/W.
        let bank = ControlBank::new([
            rotor(9, 0, Orientation::Normal),
            rotor(7, 1, Orientation::Reversed),
            rotor(5, 14, Orientation::Normal),
            rotor(3, 25, Orientation::Reversed),
            rotor(1, 4, Orientation::Normal),
        ]);

        assert_eq!(bank.outputs().map(letter), ['Z', 'C', 'M', 'W']);

        // Z/W collapse into band 8; C -> 2; M -> 6.
        let inputs = bank.index_inputs();
        assert_eq!(
            inputs.bits(),
            (1_u16 << 2) | (1_u16 << 6) | (1_u16 << 8),
        );
        assert_eq!(inputs.count(), 3);
    }

    #[test]
    fn four_control_signals_can_collapse_to_fewer_index_inputs() {
        // The fixed fixture above demonstrates the electrical OR behavior
        // across the complete control-bank path rather than only testing the
        // pure banding helper in isolation.
        let bank = ControlBank::new([
            rotor(9, 0, Orientation::Normal),
            rotor(7, 1, Orientation::Reversed),
            rotor(5, 14, Orientation::Normal),
            rotor(3, 25, Orientation::Reversed),
            rotor(1, 4, Orientation::Normal),
        ]);

        assert_eq!(bank.outputs().len(), 4);
        assert_eq!(bank.index_inputs().count(), 3);
    }

    #[test]
    fn rotor_accessor_preserves_left_to_right_slots() {
        let bank = ControlBank::new([
            rotor(0, 0, Orientation::Normal),
            rotor(1, 1, Orientation::Reversed),
            rotor(2, 2, Orientation::Normal),
            rotor(3, 3, Orientation::Reversed),
            rotor(4, 4, Orientation::Normal),
        ]);

        assert_eq!(bank.rotor(0).position(), Position26::new(0).unwrap());
        assert_eq!(bank.rotor(1).position(), Position26::new(1).unwrap());
        assert_eq!(bank.rotor(2).position(), Position26::new(2).unwrap());
        assert_eq!(bank.rotor(3).position(), Position26::new(3).unwrap());
        assert_eq!(bank.rotor(4).position(), Position26::new(4).unwrap());

        assert_eq!(bank.rotor(0).orientation(), Orientation::Normal);
        assert_eq!(bank.rotor(1).orientation(), Orientation::Reversed);
        assert_eq!(bank.rotor(3).orientation(), Orientation::Reversed);
    }
}
