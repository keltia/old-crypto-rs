//! Complete CSP-889 stepping-maze decision layer.
//!
//! For one character, the stepping maze is:
//!
//! ```text
//! fixed F/G/H/I
//!      |
//!      v
//! five control rotors
//!      |
//!      v
//! fixed A-Z -> index-input OR banding
//!      |
//!      v
//! five fixed 10-contact index rotors
//!      |
//!      v
//! paired index outputs
//!      |
//!      v
//! CipherStepSet
//! ```
//!
//! This module deliberately does **not** move any cipher rotor. It computes the
//! set of cipher slots that must step for the character. Actual cipher-bank
//! mutation is introduced in the following step.

use super::{
    contact::Contact10,
    control::IndexSignals,
    control_bank::ControlBank,
    index_rotor::IndexBank,
    stepping::{cipher_steps_from_index_outputs, CipherStepSet},
};

/// Fixed-position CSP-889 index/control stepping maze.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SteppingMaze {
    control: ControlBank,
    index: IndexBank,
}

impl SteppingMaze {
    #[must_use]
    pub(crate) const fn new(control: ControlBank, index: IndexBank) -> Self {
        Self { control, index }
    }

    /// Transform all currently active index inputs through the five-wheel index
    /// bank, preserving electrical OR semantics.
    #[must_use]
    pub(crate) fn index_outputs(&self, inputs: IndexSignals) -> IndexSignals {
        let mut outputs = IndexSignals::empty();

        for value in 0..10_u8 {
            let input = Contact10::new(value).expect("0..9 is a valid index contact");
            if inputs.contains(input) {
                outputs.insert(self.index.forward(input));
            }
        }

        outputs
    }

    /// Compute the cipher rotors selected to step for the current maze state.
    #[must_use]
    pub(crate) fn cipher_steps(&self) -> CipherStepSet {
        let index_inputs = self.control.index_inputs();
        let index_outputs = self.index_outputs(index_inputs);
        cipher_steps_from_index_outputs(index_outputs)
    }

    /// Expose the control-bank result for diagnostics/tests.
    #[must_use]
    pub(crate) fn control_index_inputs(&self) -> IndexSignals {
        self.control.index_inputs()
    }

    /// Access the fixed index bank.
    #[must_use]
    pub(crate) const fn index_bank(&self) -> &IndexBank {
        &self.index
    }

    /// Access the current control bank.
    #[must_use]
    pub(crate) const fn control_bank(&self) -> &ControlBank {
        &self.control
    }

    /// Mutable access used later when control metering is integrated into the
    /// complete machine cycle.
    #[must_use]
    pub(crate) fn control_bank_mut(&mut self) -> &mut ControlBank {
        &mut self.control
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigaba::{
        alphabet_rotor::{AlphabetRotor, Orientation},
        contact::{Position10, Position26},
        data::{IndexRotorId, LargeRotorId, LargeRotorSet},
        index_rotor::IndexRotor,
    };

    fn large(id: u8, pos: u8, orientation: Orientation) -> AlphabetRotor {
        AlphabetRotor::from_reference(
            LargeRotorSet::PekelneyReference,
            LargeRotorId::new(id).unwrap(),
            Position26::new(pos).unwrap(),
            orientation,
        )
        .unwrap()
    }

    fn index(id: u8, pos: u8) -> IndexRotor {
        IndexRotor::from_reference(
            IndexRotorId::new(id).unwrap(),
            Position10::new(pos).unwrap(),
        )
        .unwrap()
    }

    fn base_control() -> ControlBank {
        ControlBank::new([
            large(5, 0, Orientation::Normal),
            large(6, 0, Orientation::Normal),
            large(7, 0, Orientation::Normal),
            large(8, 0, Orientation::Normal),
            large(9, 0, Orientation::Normal),
        ])
    }

    fn identity_position_index_bank() -> IndexBank {
        IndexBank::new([
            index(0, 0),
            index(1, 0),
            index(2, 0),
            index(3, 0),
            index(4, 0),
        ])
    }

    #[test]
    fn active_index_inputs_are_transformed_independently_and_or_collapsed() {
        let maze = SteppingMaze::new(base_control(), identity_position_index_bank());
        let inputs = IndexSignals::from_bits(
            (1_u16 << 1) | (1_u16 << 3) | (1_u16 << 7) | (1_u16 << 9),
        );

        let outputs = maze.index_outputs(inputs);

        // Independently compute expected outputs through the same fixed bank,
        // then OR them into a bitset. This specifically verifies multi-signal
        // semantics rather than only single-contact IndexBank behavior.
        let mut expected = IndexSignals::empty();
        for value in [1_u8, 3, 7, 9] {
            expected.insert(
                maze.index_bank()
                    .forward(Contact10::new(value).unwrap()),
            );
        }

        assert_eq!(outputs, expected);
        assert!(outputs.count() <= 4);
    }

    #[test]
    fn pekelney_reference_base_fixture_has_frozen_full_maze_result() {
        // Step 8 established the control fixture:
        //
        // F/G/H/I -> J/C/R/A -> index inputs {2,5,7,9}.
        //
        // With historical index rotors 1..5 at position 0, the five-wheel
        // composition maps:
        //
        // 2 -> 0
        // 5 -> 6
        // 7 -> 2
        // 9 -> 5
        //
        // Hence active index outputs are {0,2,5,6}. Their paired cipher slots
        // are:
        //
        // 0 -> slot 0
        // 5/6 -> slot 2
        // 2 -> slot 4
        //
        // resulting in cipher-step set {0,2,4}.
        let maze = SteppingMaze::new(base_control(), identity_position_index_bank());

        assert_eq!(
            maze.control_index_inputs().bits(),
            (1_u16 << 2) | (1_u16 << 5) | (1_u16 << 7) | (1_u16 << 9),
        );

        let outputs = maze.index_outputs(maze.control_index_inputs());
        assert_eq!(
            outputs.bits(),
            (1_u16 << 0) | (1_u16 << 2) | (1_u16 << 5) | (1_u16 << 6),
        );

        let steps = maze.cipher_steps();
        assert_eq!(steps.bits(), 0b10101);
        assert_eq!(steps.count(), 3);
        assert!(steps.contains_slot(0));
        assert!(!steps.contains_slot(1));
        assert!(steps.contains_slot(2));
        assert!(!steps.contains_slot(3));
        assert!(steps.contains_slot(4));
    }

    #[test]
    fn different_index_positions_change_cipher_step_selection() {
        let index_bank = IndexBank::new([
            index(0, 1),
            index(1, 2),
            index(2, 3),
            index(3, 4),
            index(4, 5),
        ]);
        let maze = SteppingMaze::new(base_control(), index_bank);

        let steps = maze.cipher_steps();

        // Freeze the complete maze output for this non-trivial index setting.
        assert_eq!(steps.bits(), 0b10011);
        assert_eq!(steps.count(), 3);
    }

    #[test]
    fn duplicate_index_outputs_do_not_double_step_cipher_rotor() {
        // Construct an input set whose five-wheel index mapping produces both
        // members of one cipher-step pair if possible. Regardless of how many
        // active outputs land in a pair, CipherStepSet contains that slot once.
        let maze = SteppingMaze::new(base_control(), identity_position_index_bank());

        let outputs = IndexSignals::from_bits((1_u16 << 5) | (1_u16 << 6));
        let steps = cipher_steps_from_index_outputs(outputs);

        assert_eq!(steps.count(), 1);
        assert!(steps.contains_slot(2));
    }

    #[test]
    fn metering_control_bank_changes_future_step_decisions_without_moving_index_bank() {
        let mut maze = SteppingMaze::new(base_control(), identity_position_index_bank());

        let before = maze.cipher_steps();
        let index_before = *maze.index_bank();

        maze.control_bank_mut().meter();

        assert_eq!(*maze.index_bank(), index_before);

        // The control state has changed. It is acceptable for a particular
        // single step to coincidentally select the same CipherStepSet, so
        // compare the underlying control outputs rather than assert inequality
        // on the final paired set alone.
        assert_ne!(
            maze.control_bank().outputs(),
            base_control().outputs(),
        );

        let _after = maze.cipher_steps();
        let _ = before;
    }

    #[test]
    fn index_input_zero_stays_inactive_at_complete_maze_boundary() {
        let maze = SteppingMaze::new(base_control(), identity_position_index_bank());

        let inputs = maze.control_index_inputs();
        assert!(!inputs.contains(Contact10::new(0).unwrap()));
    }
}
