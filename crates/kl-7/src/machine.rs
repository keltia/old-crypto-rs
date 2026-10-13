//! Internal runtime engine for the TSEC/KL-7 cipher machine.
//!
//! `Kl7Core` maintains the cycle-by-cycle machine state, including the 8 rotors,
//! the 7 actuator notch rings, keystroke counter, and stepping execution.

use super::{
    actuator::{ActuatorState, ACTUATOR_SWITCH_COUNT},
    contact::{Contact26, Position36},
    maze::{trace_maze, MazeDirection, MazeError},
    notch_ring::NotchRing,
    rotor::Rotor,
    stepping::{evaluate_stepping, RotorStepSet, DRUM_ROTOR_COUNT},
};

/// Mutable core state of the KL-7 cipher machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Kl7Core {
    rotors: [Rotor; DRUM_ROTOR_COUNT],
    rings: [NotchRing; ACTUATOR_SWITCH_COUNT],
    ring_offsets: [Position36; ACTUATOR_SWITCH_COUNT],
    counter: usize,
}

impl Kl7Core {
    /// Create a new core instance with given mounted rotors and notch rings.
    #[must_use]
    pub const fn new(
        rotors: [Rotor; DRUM_ROTOR_COUNT],
        rings: [NotchRing; ACTUATOR_SWITCH_COUNT],
        ring_offsets: [Position36; ACTUATOR_SWITCH_COUNT],
    ) -> Self {
        Self {
            rotors,
            rings,
            ring_offsets,
            counter: 0,
        }
    }

    /// Return reference to the 8 rotors in the drum.
    #[must_use]
    pub const fn rotors(&self) -> &[Rotor; DRUM_ROTOR_COUNT] {
        &self.rotors
    }

    /// Return mutable reference to the 8 rotors in the drum.
    pub fn rotors_mut(&mut self) -> &mut [Rotor; DRUM_ROTOR_COUNT] {
        &mut self.rotors
    }

    /// Return the keystroke counter.
    #[must_use]
    pub const fn counter(&self) -> usize {
        self.counter
    }

    /// Reset the keystroke counter to 0.
    pub fn reset_counter(&mut self) {
        self.counter = 0;
    }

    /// Step the machine by one cycle according to current actuator switch states.
    pub fn step(&mut self) -> RotorStepSet {
        let actuators = ActuatorState::sense(&self.rotors, &self.rings, &self.ring_offsets);
        let steps = evaluate_stepping(&actuators);

        for (i, rotor) in self.rotors.iter_mut().enumerate() {
            if steps.should_step(i) {
                rotor.step();
            }
        }

        steps
    }

    /// Encipher one alphabet contact (`A=0..Z=25`), then advance the machine.
    pub fn encipher_contact(&mut self, input: Contact26) -> Result<Contact26, MazeError> {
        let (output, _passes) = trace_maze(&self.rotors, input, MazeDirection::Forward)?;
        self.step();
        self.counter += 1;
        Ok(output)
    }

    /// Decipher one alphabet contact (`A=0..Z=25`), then advance the machine.
    pub fn decipher_contact(&mut self, input: Contact26) -> Result<Contact26, MazeError> {
        let (output, _passes) = trace_maze(&self.rotors, input, MazeDirection::Backward)?;
        self.step();
        self.counter += 1;
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Kl7Config;

    #[test]
    fn uss_beagle_core_enciphers_and_deciphers_reciprocally() {
        let config = Kl7Config::uss_beagle();
        let mut enc_core = config.build_core();
        let mut dec_core = config.build_core();

        let message = "HELLOWORLD";
        let mut cipher_contacts = Vec::new();

        for ch in message.chars() {
            let in_contact = Contact26::from_ascii_letter(ch).unwrap();
            let out_contact = enc_core.encipher_contact(in_contact).unwrap();
            cipher_contacts.push(out_contact);
        }

        let mut decrypted_chars = String::new();
        for contact in cipher_contacts {
            let out_contact = dec_core.decipher_contact(contact).unwrap();
            decrypted_chars.push(out_contact.to_ascii_char());
        }

        assert_eq!(decrypted_chars, message);
    }
}
