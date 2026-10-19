//! Stateful M-209 operation: convert at the current wheel positions, then step.
//!
//! A character is always converted before all six wheels advance. This module
//! handles raw 26-contact operations only; historical text conventions and
//! message indicators are introduced in later steps.

use crate::{Contact, M209Core, WHEEL_COUNT, WheelPosition};

/// Stateful cipher machine with a saved initial configuration for reset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct M209Machine {
    core: M209Core,
    initial: M209Core,
}

impl M209Machine {
    /// Start at the validated wheel positions provided by the frozen core.
    pub fn new(core: M209Core) -> Self {
        Self {
            initial: core.clone(),
            core,
        }
    }

    /// Current wheel positions, in physical wheel order (1 through 6).
    pub fn positions(&self) -> [WheelPosition; WHEEL_COUNT] {
        self.core.wheels().positions()
    }

    /// Inspect the current frozen state without advancing the machine.
    pub const fn core(&self) -> &M209Core {
        &self.core
    }

    /// Convert a single contact and advance all six wheels exactly once.
    ///
    /// Encryption and decryption use the same reciprocal transformation.
    pub fn convert_contact(&mut self, input: Contact) -> Contact {
        let output = self.core.convert_contact(input);
        self.core.advance_wheels();
        output
    }

    /// Convert successive contacts without resetting between calls.
    ///
    /// This method has no text mapping, padding, or indicator handling.
    pub fn convert_contacts(&mut self, input: &[Contact]) -> Vec<Contact> {
        input.iter().copied().map(|contact| self.convert_contact(contact)).collect()
    }

    /// Restore the complete initial machine state, including wheel positions.
    pub fn reset(&mut self) {
        self.core.clone_from(&self.initial);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{MANUAL_1944_PINS, manual_1944_drum, parse_pin_fixture};
    use crate::{LugDrum, WheelBank, WheelId};

    fn sample_machine() -> M209Machine {
        let patterns = parse_pin_fixture(MANUAL_1944_PINS).unwrap();
        let positions = core::array::from_fn(|index| {
            WheelId::new(index as u8 + 1)
                .unwrap()
                .position_for_letter('A')
                .unwrap()
        });

        let wheels = WheelBank::new(patterns, positions).unwrap();
        M209Machine::new(M209Core::new(wheels, LugDrum::new(manual_1944_drum())))
    }

    #[test]
    fn first_character_is_converted_before_stepping() {
        let mut machine = sample_machine();
        let first = machine.convert_contact(Contact::A);

        assert_eq!(first.letter(), 'T');
        assert_eq!(machine.core().wheels().visible_letters(), "BBBBBB");
        assert_eq!(machine.core().wheels().sensed_letters(), "QPONML");
    }

    #[test]
    fn exactly_one_step_per_processed_character() {
        let mut machine = sample_machine();

        for _ in 0..4 {
            machine.convert_contact(Contact::A);
        }

        assert_eq!(machine.core().wheels().visible_letters(), "EEEEEE");
    }

    #[test]
    fn encoder_and_decoder_share_identical_state_evolution() {
        let plaintext = [Contact::A; 64];
        let mut encoder = sample_machine();
        let mut decoder = sample_machine();
        let ciphertext = encoder.convert_contacts(&plaintext);
        let decoded = decoder.convert_contacts(&ciphertext);

        assert_eq!(decoded, plaintext);
        assert_eq!(decoder.positions(), encoder.positions());
    }

    #[test]
    fn streaming_chunks_equal_one_continuous_call() {
        let input = [Contact::A; 81];
        let mut continuous = sample_machine();
        let mut streaming = sample_machine();

        let expected = continuous.convert_contacts(&input);
        let mut actual = streaming.convert_contacts(&input[..17]);
        actual.extend(streaming.convert_contacts(&input[17..54]));
        actual.extend(streaming.convert_contacts(&input[54..]));

        assert_eq!(actual, expected);
        assert_eq!(streaming.positions(), continuous.positions());
    }

    #[test]
    fn reset_restores_initial_state_and_replays_output() {
        let mut machine = sample_machine();
        let initial = machine.clone();
        let input = [Contact::A; 30];
        let first = machine.convert_contacts(&input);

        machine.reset();
        assert_eq!(machine, initial);
        assert_eq!(machine.convert_contacts(&input), first);
    }

    #[test]
    fn inspecting_frozen_core_does_not_advance() {
        let machine = sample_machine();
        let before = machine.positions();

        for _ in 0..10 {
            assert_eq!(machine.core().convert_contact(Contact::A).letter(), 'T');
        }

        assert_eq!(machine.positions(), before);
    }
}
