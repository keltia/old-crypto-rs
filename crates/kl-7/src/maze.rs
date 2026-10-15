//! Multi-pass re-entry maze and electrical circuit engine for TSEC/KL-7.
//!
//! # Electrical Signal Conduction
//!
//! Electrical current enters the 8-rotor drum via one of the 26 alphabet contacts on the entry endplate.
//! It passes through all 8 rotors in sequence. When exiting at the opposite endplate:
//! - If it lands on one of the 26 alphabet pins, conduction terminates and that letter is printed/outputted.
//! - If it lands on one of the 10 re-entry pins (0..9), the signal is routed via the external wiring
//!   harness back into the matching re-entry pin on the entry endplate for another pass through the drum.
//!
//! This re-flexing process typically repeats 1 to 11 times until reaching an alphabet terminal.

use super::{
    contact::Contact26,
    data::{letter_to_pin, pin_to_terminal, reentry_to_pin, BasePlateTerminal},
    rotor::Rotor,
    stepping::DRUM_ROTOR_COUNT,
};
use core::fmt;

/// Maximum allowable passes through the rotor drum before detecting an infinite cycle.
pub const MAX_MAZE_PASSES: usize = 32;

/// Direction of signal conduction through the rotor drum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MazeDirection {
    /// Encipher mode: Left endplate -> Rotors 0..7 -> Right endplate.
    Forward,
    /// Decipher mode: Right endplate -> Rotors 7..0 -> Left endplate.
    Backward,
}

/// Error encountered during maze signal routing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MazeError {
    /// Signal entered an infinite loop without exiting at an alphabet contact.
    InfiniteLoop {
        start_letter: Contact26,
        passes: usize,
    },
}

impl fmt::Display for MazeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::InfiniteLoop { start_letter, passes } => write!(
                f,
                "re-entry maze infinite loop detected starting from letter {} after {} passes",
                start_letter, passes
            ),
        }
    }
}

impl std::error::Error for MazeError {}

/// Trace electrical signal through the 8-rotor drum with re-entry loops.
///
/// Returns the resulting output letter contact and the number of passes through the drum.
pub fn trace_maze(
    rotors: &[Rotor; DRUM_ROTOR_COUNT],
    input_letter: Contact26,
    direction: MazeDirection,
) -> Result<(Contact26, usize), MazeError> {
    let mut current_pin = letter_to_pin(input_letter);
    let mut passes = 0;

    loop {
        passes += 1;
        if passes > MAX_MAZE_PASSES {
            return Err(MazeError::InfiniteLoop {
                start_letter: input_letter,
                passes,
            });
        }

        // Pass signal through all 8 rotors in the specified direction
        let exit_pin = match direction {
            MazeDirection::Forward => {
                let mut pin = current_pin;
                for rotor in rotors {
                    pin = rotor.forward(pin);
                }
                pin
            }
            MazeDirection::Backward => {
                let mut pin = current_pin;
                for rotor in rotors.iter().rev() {
                    pin = rotor.backward(pin);
                }
                pin
            }
        };

        // Check if exit pin is a letter or a re-entry loop
        match pin_to_terminal(exit_pin) {
            BasePlateTerminal::Letter(out_letter) => {
                return Ok((out_letter, passes));
            }
            BasePlateTerminal::Reentry(wire) => {
                // Re-enter on the input side at the matching loop wire
                current_pin = reentry_to_pin(wire);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact::Position36;
    use crate::data::RotorId;

    fn test_rotor_drum() -> [Rotor; DRUM_ROTOR_COUNT] {
        [
            Rotor::from_reference(RotorId::E, Position36::new(3).unwrap(), Position36::new(3).unwrap()),
            Rotor::from_reference(RotorId::H, Position36::new(27).unwrap(), Position36::new(27).unwrap()),
            Rotor::from_reference(RotorId::F, Position36::new(3).unwrap(), Position36::new(3).unwrap()),
            Rotor::from_reference(RotorId::L, Position36::new(15).unwrap(), Position36::new(15).unwrap()),
            Rotor::from_reference(RotorId::I, Position36::new(8).unwrap(), Position36::new(8).unwrap()),
            Rotor::from_reference(RotorId::A, Position36::new(31).unwrap(), Position36::new(31).unwrap()),
            Rotor::from_reference(RotorId::G, Position36::new(7).unwrap(), Position36::new(7).unwrap()),
            Rotor::from_reference(RotorId::B, Position36::new(10).unwrap(), Position36::new(10).unwrap()),
        ]
    }

    #[test]
    fn maze_signal_path_is_bijective_and_reciprocal_for_fixed_drum_state() {
        let drum = test_rotor_drum();

        for letter_idx in 0..26 {
            let input = Contact26::new(letter_idx).unwrap();
            let (ciphertext, enc_passes) = trace_maze(&drum, input, MazeDirection::Forward).unwrap();
            assert!((1..=16).contains(&enc_passes), "Passes count: {}", enc_passes);

            let (decrypted, dec_passes) = trace_maze(&drum, ciphertext, MazeDirection::Backward).unwrap();
            assert_eq!(decrypted, input, "Decryption mismatch for {}", input);
            assert_eq!(dec_passes, enc_passes, "Pass count mismatch for {}", input);
        }
    }

    #[test]
    fn various_rotor_positions_all_terminate_and_round_trip() {
        let mut drum = test_rotor_drum();

        for step in 0..50 {
            for r in &mut drum {
                r.set_win_pos(Position36::new((step * 3 + r.id().index() as u8) % 36).unwrap());
            }

            for letter_idx in 0..26 {
                let input = Contact26::new(letter_idx).unwrap();
                let (ciphertext, _) = trace_maze(&drum, input, MazeDirection::Forward).unwrap();
                let (decrypted, _) = trace_maze(&drum, ciphertext, MazeDirection::Backward).unwrap();
                assert_eq!(decrypted, input);
            }
        }
    }
}
