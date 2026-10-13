//! TSEC/KL-7 36-contact rotor primitive.
//!
//! Models a single 36-contact rotor with forward/backward signal mapping,
//! rotational window position (`win_pos`), and alphabet ring offset (`alpha_pos`).

use super::{
    contact::{Contact36, Position36, ROTOR_CONTACTS},
    data::{reference_rotor_permutation, RotorId},
    permutation::Permutation,
};

/// Internal wiring permutation of a 36-contact KL-7 rotor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RotorWiring {
    permutation: Permutation<36>,
}

impl RotorWiring {
    /// Construct rotor wiring from a validated 36-element permutation.
    #[must_use]
    pub const fn from_permutation(permutation: Permutation<36>) -> Self {
        Self { permutation }
    }

    /// Construct standard reference rotor wiring for a named rotor core.
    #[must_use]
    pub fn reference(id: RotorId) -> Self {
        Self {
            permutation: reference_rotor_permutation(id),
        }
    }

    /// Forward permutation mapping.
    #[must_use]
    pub const fn forward(&self, pin: u8) -> u8 {
        self.permutation.forward(pin)
    }

    /// Inverse (backward) permutation mapping.
    #[must_use]
    pub const fn inverse(&self, pin: u8) -> u8 {
        self.permutation.inverse(pin)
    }

    /// Return reference to the underlying permutation.
    #[must_use]
    pub const fn permutation(&self) -> &Permutation<36> {
        &self.permutation
    }
}

/// A mounted 36-contact KL-7 cipher rotor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rotor {
    id: RotorId,
    wiring: RotorWiring,
    win_pos: Position36,
    alpha_pos: Position36,
}

impl Rotor {
    /// Construct a rotor with given ID, wiring, start window position, and alphabet ring offset.
    #[must_use]
    pub const fn new(
        id: RotorId,
        wiring: RotorWiring,
        win_pos: Position36,
        alpha_pos: Position36,
    ) -> Self {
        Self {
            id,
            wiring,
            win_pos,
            alpha_pos,
        }
    }

    /// Construct a reference rotor core with given settings.
    #[must_use]
    pub fn from_reference(
        id: RotorId,
        win_pos: Position36,
        alpha_pos: Position36,
    ) -> Self {
        Self::new(id, RotorWiring::reference(id), win_pos, alpha_pos)
    }

    /// Return the rotor ID.
    #[must_use]
    pub const fn id(&self) -> RotorId {
        self.id
    }

    /// Current rotational window position.
    #[must_use]
    pub const fn win_pos(&self) -> Position36 {
        self.win_pos
    }

    /// Set the rotational window position.
    pub fn set_win_pos(&mut self, pos: Position36) {
        self.win_pos = pos;
    }

    /// Alphabet ring offset.
    #[must_use]
    pub const fn alpha_pos(&self) -> Position36 {
        self.alpha_pos
    }

    /// Set the alphabet ring offset.
    pub fn set_alpha_pos(&mut self, pos: Position36) {
        self.alpha_pos = pos;
    }

    /// Advance the rotor by one step (+1 position modulo 36).
    pub fn step(&mut self) {
        self.win_pos = self.win_pos.step();
    }

    /// Encipher a contact forward (left to right through the rotor drum).
    #[must_use]
    pub fn forward(&self, contact: Contact36) -> Contact36 {
        let m = ROTOR_CONTACTS as u16;
        let in_pin = (contact.get() as u16 + self.win_pos.get() as u16 + self.alpha_pos.get() as u16) % m;
        let mapped = self.wiring.forward(in_pin as u8) as u16;
        let out_pin = (mapped + (m * 2) - self.alpha_pos.get() as u16 - self.win_pos.get() as u16) % m;
        Contact36::new(out_pin as u8).expect("valid contact")
    }

    /// Decipher a contact backward (right to left through the rotor drum).
    #[must_use]
    pub fn backward(&self, contact: Contact36) -> Contact36 {
        let m = ROTOR_CONTACTS as u16;
        let in_pin = (contact.get() as u16 + self.win_pos.get() as u16 + self.alpha_pos.get() as u16) % m;
        let mapped = self.wiring.inverse(in_pin as u8) as u16;
        let out_pin = (mapped + (m * 2) - self.alpha_pos.get() as u16 - self.win_pos.get() as u16) % m;
        Contact36::new(out_pin as u8).expect("valid contact")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotor_forward_and_backward_are_inverses() {
        let rotor = Rotor::from_reference(
            RotorId::A,
            Position36::new(14).unwrap(),
            Position36::new(7).unwrap(),
        );

        for pin in 0..36 {
            let c = Contact36::new(pin).unwrap();
            let fwd = rotor.forward(c);
            let bwd = rotor.backward(fwd);
            assert_eq!(bwd, c, "Round trip failed for pin {}", pin);
        }
    }

    #[test]
    fn rotor_stepping_updates_window_position() {
        let mut rotor = Rotor::from_reference(
            RotorId::B,
            Position36::new(35).unwrap(),
            Position36::ZERO,
        );
        assert_eq!(rotor.win_pos().get(), 35);
        rotor.step();
        assert_eq!(rotor.win_pos().get(), 0);
        rotor.step();
        assert_eq!(rotor.win_pos().get(), 1);
    }
}
