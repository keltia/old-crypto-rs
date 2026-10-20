//! Stateful SG-41 character processing.
//!
//! Each crank turn applies phases I and II, senses the displacement pins,
//! converts one letter through the print head, then applies phases III and IV.

use super::displacement::{Displacement, sense_displacement};
use super::print_head::{decipher_letter, encipher_letter};
use super::stepping::{SteppingTrace, step_after_cipher, step_before_cipher};
use super::wheel_bank::WheelBank;

/// A complete character operation, including the cage and stepping trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CharacterCycle {
    pub output: char,
    pub displacement: Displacement,
    pub stepping: SteppingTrace,
}

/// Stateful alphabetic SG-41 cipher engine with a fixed wheel configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sg41Core {
    wheels: WheelBank,
}

impl Sg41Core {
    pub const fn new(wheels: WheelBank) -> Self {
        Self { wheels }
    }

    /// Current wheel settings; these change after each accepted character.
    pub const fn wheel_bank(&self) -> &WheelBank {
        &self.wheels
    }

    /// Encipher one uppercase ASCII letter and advance the machine one turn.
    /// Invalid input returns `None` without changing the wheel state.
    pub fn encipher_char(&mut self, plaintext: char) -> Option<CharacterCycle> {
        self.process(plaintext, true)
    }

    /// Decipher one uppercase ASCII letter with the same crank sequence.
    /// Invalid input returns `None` without changing the wheel state.
    pub fn decipher_char(&mut self, ciphertext: char) -> Option<CharacterCycle> {
        self.process(ciphertext, false)
    }

    fn process(&mut self, letter: char, encipher: bool) -> Option<CharacterCycle> {
        // Validate before stepping; a rejected character must not turn the crank.
        if !letter.is_ascii_uppercase() {
            return None;
        }

        let pre_cipher = step_before_cipher(&mut self.wheels);
        let displacement = sense_displacement(&self.wheels);

        let output = if encipher {
            encipher_letter(letter, displacement.steps)
        } else {
            decipher_letter(letter, displacement.steps)
        }
        .expect("uppercase input and 0..=25 cage displacement are valid");

        let stepping = step_after_cipher(&mut self.wheels, pre_cipher);

        Some(CharacterCycle {
            output,
            displacement,
            stepping,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PinPattern, WheelId, WheelPosition, WHEEL_COUNT};

    const PINS: [&str; WHEEL_COUNT] = [
        "0001101011000100010001101",
        "0110100100001011100101100",
        "11001001000100100100010",
        "01001000111010001110010",
        "001001001010000101011010",
        "011001100110001011010100",
    ];

    const PLAINTEXT: &str = "SCHLUESSELGERAETVIEREINSWANDERER";
    const CIPHERTEXT: &str = "IHEPLRETQSDSNDCWHPIVVGLYMHOWSJQS";

    fn reference_core() -> Sg41Core {
        let positions = std::array::from_fn(|i| {
            let wheel = WheelId::new(i as u8 + 1).unwrap();
            WheelPosition::new(wheel, [0, 1, 2, 3, 0, 0][i]).unwrap()
        });
        let pins = std::array::from_fn(|i| {
            let wheel = WheelId::new(i as u8 + 1).unwrap();
            PinPattern::from_table_bits(wheel, PINS[i]).unwrap()
        });

        Sg41Core::new(WheelBank::new(positions, pins).unwrap())
    }

    #[test]
    fn historical_32_letter_known_answer() {
        let mut core = reference_core();
        let ciphertext: String = PLAINTEXT
            .chars()
            .map(|ch| core.encipher_char(ch).unwrap().output)
            .collect();

        assert_eq!(ciphertext, CIPHERTEXT);
    }

    #[test]
    fn reciprocal_decryption_with_identical_starting_settings() {
        let mut core = reference_core();
        let plaintext: String = CIPHERTEXT
            .chars()
            .map(|ch| core.decipher_char(ch).unwrap().output)
            .collect();

        assert_eq!(plaintext, PLAINTEXT);
    }

    #[test]
    fn cipher_cycle_reports_intermediate_state_at_correct_boundary() {
        let mut core = reference_core();
        let first = core.encipher_char('S').unwrap();

        assert_eq!(first.output, 'I');
        assert_eq!(first.displacement.steps, 6);
        assert_eq!(core.wheel_bank().positions(), first.stepping.final_positions);
    }

    #[test]
    fn invalid_input_does_not_change_machine_state() {
        let mut core = reference_core();
        let before = core.wheel_bank().positions();

        assert!(core.encipher_char(' ').is_none());
        assert!(core.decipher_char('a').is_none());
        assert!(core.encipher_char('3').is_none());
        assert_eq!(core.wheel_bank().positions(), before);
    }

    #[test]
    fn character_cycles_match_independent_step_and_cage_execution() {
        let mut core = reference_core();
        let mut wheels = core.wheel_bank().clone();

        for ch in PLAINTEXT.chars() {
            let pre_cipher = step_before_cipher(&mut wheels);
            let expected_displacement = sense_displacement(&wheels);
            let expected_output = encipher_letter(ch, expected_displacement.steps).unwrap();
            let expected_step = step_after_cipher(&mut wheels, pre_cipher);

            let cycle = core.encipher_char(ch).unwrap();
            assert_eq!(cycle.output, expected_output);
            assert_eq!(cycle.displacement, expected_displacement);
            assert_eq!(cycle.stepping, expected_step);
            assert_eq!(core.wheel_bank().positions(), wheels.positions());
        }
    }
}
