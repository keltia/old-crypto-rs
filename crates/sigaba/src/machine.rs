//! Stateful CSP-889 SIGABA character cycle.
//!
//! This composes the new cipher bank and stepping maze into the actual
//! per-character machine state transition.
//!
//! The cycle order follows the Pekelney-derived ECM Mark II reference model:
//!
//! ```text
//! 1. transform the input through the cipher bank using the current state;
//! 2. derive the cipher step set from the current control/index maze;
//! 3. step the selected cipher rotors;
//! 4. meter the control rotors.
//! ```
//!
//! Encipher and decipher use inverse electrical traversal through the cipher
//! bank but **identical stepping state evolution**.

use super::{
    cipher_bank::CipherBank,
    contact::Contact26,
    maze::SteppingMaze,
    rotor_set::{MountedRotorTransforms, RotorSet},
};

#[cfg(test)]
use super::stepping::CipherStepSet;

/// Electrical direction through the cipher bank.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CipherDirection {
    Encipher,
    Decipher,
}

/// Complete mutable CSP-889 rotor state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SigabaCore {
    cipher: CipherBank,
    maze: SteppingMaze,
}

pub(crate) struct SigabaTables<'a> {
    cipher: [&'a MountedRotorTransforms; 5],
    control: [&'a MountedRotorTransforms; 5],
}

impl SigabaCore {
    #[must_use]
    pub(crate) const fn new(cipher: CipherBank, maze: SteppingMaze) -> Self {
        Self { cipher, maze }
    }

    /// Process one 26-contact symbol and advance the complete machine state.
    #[must_use]
    pub(crate) fn process_contact(
        &mut self,
        tables: &SigabaTables<'_>,
        input: Contact26,
        direction: CipherDirection,
    ) -> Contact26 {
        // The electrical cipher transform uses the rotor state *before* this
        // character's stepping decision is applied.
        let output = match direction {
            CipherDirection::Encipher => self.cipher.encipher_with(&tables.cipher, input),
            CipherDirection::Decipher => self.cipher.decipher_with(&tables.cipher, input),
        };

        // The stepping maze is evaluated from the current control/index state.
        let steps = self.maze.cipher_steps_with(&tables.control);

        // Cipher rotors move after the character has been electrically
        // transformed.
        self.cipher.apply_steps(steps);

        // Control metering also occurs after the current character's stepping
        // decision has been derived.
        self.maze.control_bank_mut().meter();

        output
    }

    #[must_use]
    pub(crate) fn encipher_contact_with(
        &mut self,
        tables: &SigabaTables<'_>,
        input: Contact26,
    ) -> Contact26 {
        self.process_contact(tables, input, CipherDirection::Encipher)
    }

    #[must_use]
    pub(crate) fn decipher_contact_with(
        &mut self,
        tables: &SigabaTables<'_>,
        input: Contact26,
    ) -> Contact26 {
        self.process_contact(tables, input, CipherDirection::Decipher)
    }

    pub(crate) fn resolve_tables<'a>(
        &self,
        rotor_set: &'a RotorSet,
    ) -> SigabaTables<'a> {
        SigabaTables {
            cipher: self.cipher.resolve(rotor_set),
            control: self.maze.control_bank().resolve(rotor_set),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn encipher_contact(&mut self, input: Contact26) -> Contact26 {
        let tables = self.resolve_tables(super::data::reference_rotor_set().unwrap());
        self.encipher_contact_with(&tables, input)
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn decipher_contact(&mut self, input: Contact26) -> Contact26 {
        let tables = self.resolve_tables(super::data::reference_rotor_set().unwrap());
        self.decipher_contact_with(&tables, input)
    }

    /// Current cipher-rotor positions in physical left-to-right order.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn cipher_positions(&self) -> [u8; 5] {
        self.cipher.positions()
    }

    /// Current control-rotor positions in physical left-to-right order.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn control_positions(&self) -> [u8; 5] {
        self.maze.control_bank().positions()
    }

    /// Current cipher-step decision without mutating machine state.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn current_cipher_steps(&self) -> CipherStepSet {
        self.maze.cipher_steps()
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn cipher_bank(&self) -> &CipherBank {
        &self.cipher
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn stepping_maze(&self) -> &SteppingMaze {
        &self.maze
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        alphabet_rotor::{AlphabetRotor, Orientation},
        contact::{Contact10, Position10, Position26},
        control_bank::ControlBank,
        data::{IndexRotorId, LargeRotorId, LargeRotorSet},
        index_rotor::{IndexBank, IndexRotor},
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

    fn contact(letter: u8) -> Contact26 {
        Contact26::new(letter - b'A').unwrap()
    }

    fn base_core() -> SigabaCore {
        let cipher = CipherBank::new([
            large(0, 0, Orientation::Normal),
            large(1, 0, Orientation::Normal),
            large(2, 0, Orientation::Normal),
            large(3, 0, Orientation::Normal),
            large(4, 0, Orientation::Normal),
        ]);

        let control = ControlBank::new([
            large(5, 0, Orientation::Normal),
            large(6, 0, Orientation::Normal),
            large(7, 0, Orientation::Normal),
            large(8, 0, Orientation::Normal),
            large(9, 0, Orientation::Normal),
        ]);

        let index = IndexBank::new([
            index(0, 0),
            index(1, 0),
            index(2, 0),
            index(3, 0),
            index(4, 0),
        ]);

        SigabaCore::new(cipher, SteppingMaze::new(control, index))
    }

    #[test]
    fn first_character_uses_pre_step_cipher_positions() {
        let mut core = base_core();
        let before = *core.cipher_bank();

        let input = contact(b'A');
        let expected = before.encipher(input);
        let output = core.encipher_contact(input);

        assert_eq!(output, expected);

        // Base Step-10 fixture selects cipher slots {0,2,4}.
        assert_eq!(core.cipher_positions(), [25, 0, 25, 0, 25]);
    }

    #[test]
    fn first_character_meters_control_after_step_decision() {
        let mut core = base_core();

        assert_eq!(core.current_cipher_steps().bits(), 0b10101);
        assert_eq!(core.control_positions(), [0, 0, 0, 0, 0]);

        let _ = core.encipher_contact(contact(b'A'));

        // Fast control slot is array index 2 and moves A -> Z in normal
        // orientation. Other metered rotors remain unchanged because fast was
        // not at O before this step.
        assert_eq!(core.control_positions(), [0, 0, 25, 0, 0]);
    }

    #[test]
    fn encipher_and_decipher_have_identical_state_evolution() {
        let mut enc = base_core();
        let mut dec = base_core();

        for ch in b"THEQUICKBROWNFOX" {
            let input = Contact26::new(*ch - b'A').unwrap();

            let _ = enc.encipher_contact(input);
            let _ = dec.decipher_contact(input);

            assert_eq!(enc.cipher_positions(), dec.cipher_positions());
            assert_eq!(enc.control_positions(), dec.control_positions());
            assert_eq!(enc.current_cipher_steps(), dec.current_cipher_steps());
        }
    }

    #[test]
    fn stateful_round_trip_works_when_both_machines_start_from_same_key() {
        let plaintext = b"THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG";

        let mut enc = base_core();
        let ciphertext: Vec<Contact26> = plaintext
            .iter()
            .map(|&ch| enc.encipher_contact(Contact26::new(ch - b'A').unwrap()))
            .collect();

        let mut dec = base_core();
        let recovered: String = ciphertext
            .into_iter()
            .map(|contact| {
                let plain = dec.decipher_contact(contact);
                char::from(b'A' + plain.get())
            })
            .collect();

        assert_eq!(recovered, "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG");
    }

    #[test]
    fn state_changes_once_per_processed_contact() {
        let mut core = base_core();

        for _ in 0..26 {
            let previous_control = core.control_positions();
            let previous_cipher = core.cipher_positions();
            let steps = core.current_cipher_steps();

            let _ = core.encipher_contact(contact(b'A'));

            // Exactly the selected cipher slots move one step.
            for (slot, &before) in previous_cipher.iter().enumerate() {
                let after = core.cipher_positions()[slot];

                if steps.contains_slot(slot) {
                    assert_eq!(after, (before + 25) % 26);
                } else {
                    assert_eq!(after, before);
                }
            }

            // During the first 26 base-state characters, fast control rotor is
            // the only control rotor that necessarily moves each character.
            assert_eq!(
                core.control_positions()[2],
                (previous_control[2] + 25) % 26,
            );
        }
    }

    #[test]
    fn index_bank_remains_stationary_through_character_processing() {
        let mut core = base_core();

        let before = core
            .stepping_maze()
            .index_bank();
        let before = [
            before.rotor(0).position().get(),
            before.rotor(1).position().get(),
            before.rotor(2).position().get(),
            before.rotor(3).position().get(),
            before.rotor(4).position().get(),
        ];

        for ch in b"SIGABATEST" {
            let _ = core.encipher_contact(Contact26::new(*ch - b'A').unwrap());
        }

        let after = core
            .stepping_maze()
            .index_bank();
        let after = [
            after.rotor(0).position().get(),
            after.rotor(1).position().get(),
            after.rotor(2).position().get(),
            after.rotor(3).position().get(),
            after.rotor(4).position().get(),
        ];

        assert_eq!(before, after);
    }

    #[test]
    fn electrical_inverse_is_correct_at_each_evolving_state() {
        // Clone the current state before every character. Encipher with one
        // clone and decipher the resulting contact with the other clone. Since
        // both begin that character in the same state, the electrical paths
        // must be inverses and then both states must evolve identically.
        let mut state = base_core();

        for ch in b"ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
            let input = Contact26::new(*ch - b'A').unwrap();

            let mut enc = state;
            let ciphertext = enc.encipher_contact(input);

            let mut dec = state;
            let recovered = dec.decipher_contact(ciphertext);

            assert_eq!(recovered, input);
            assert_eq!(enc.cipher_positions(), dec.cipher_positions());
            assert_eq!(enc.control_positions(), dec.control_positions());

            state = enc;
        }
    }

    #[test]
    fn control_carry_affects_the_next_character_not_the_current_decision() {
        // Place fast control rotor at O. The current cipher-step decision must
        // be derived from the O-state, then fast/medium move afterwards.
        let cipher = CipherBank::new([
            large(0, 0, Orientation::Normal),
            large(1, 0, Orientation::Normal),
            large(2, 0, Orientation::Normal),
            large(3, 0, Orientation::Normal),
            large(4, 0, Orientation::Normal),
        ]);

        let control = ControlBank::new([
            large(5, 0, Orientation::Normal),
            large(6, 0, Orientation::Normal),
            large(7, 14, Orientation::Normal), // fast O
            large(8, 0, Orientation::Normal),
            large(9, 0, Orientation::Normal),
        ]);

        let index = IndexBank::new([
            index(0, 0),
            index(1, 0),
            index(2, 0),
            index(3, 0),
            index(4, 0),
        ]);

        let mut core = SigabaCore::new(cipher, SteppingMaze::new(control, index));
        let steps_before = core.current_cipher_steps();

        let _ = core.encipher_contact(contact(b'A'));

        // Fast O->N and medium A->Z.
        assert_eq!(core.control_positions(), [0, 0, 13, 25, 0]);

        // The post-character decision is allowed to differ; what matters is
        // that the cipher positions reflect the pre-meter step set.
        for slot in 0..5 {
            let expected = if steps_before.contains_slot(slot) { 25 } else { 0 };
            assert_eq!(core.cipher_positions()[slot], expected);
        }
    }

    #[test]
    fn contact10_type_remains_distinct_at_machine_boundary() {
        // Compile-time type distinction is the main guarantee; this small test
        // also keeps the index coordinate type live in this module's fixture.
        assert_eq!(Contact10::new(9).unwrap().get(), 9);
    }
}
