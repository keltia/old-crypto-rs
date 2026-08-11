//! Static angular position of a mounted Fialka rotor.
//!
//! A rotor position is the letter currently aligned with the machine index.
//! In the documented base position `А`, machine and rotor contact coordinates
//! coincide.  If the rotor is set to `Б`, fixed machine contact `А` aligns with
//! rotor contact `Б`, and so on around the 30-contact circle.

use super::Contact;

/// Angular position of a rotor, expressed in Fialka's 30-position alphabet.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RotorPosition(Contact);

impl RotorPosition {
    /// Construct a position from its zero-based index (`А == 0`, `Б == 1`, ...).
    #[must_use]
    pub const fn new(value: u8) -> Option<Self> {
        match Contact::new(value) {
            Some(contact) => Some(Self(contact)),
            None => None,
        }
    }

    /// Return the zero-based position index.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0.get()
    }

    /// Convert a fixed machine contact into the coordinate frame of the rotor.
    ///
    /// At position `p`, machine contact `x` meets rotor contact `x + p`.
    #[must_use]
    pub(crate) fn to_rotor_frame(self, contact: Contact) -> Contact {
        contact.offset(i16::from(self.get()))
    }

    /// Convert a rotor-local contact back into the fixed machine frame.
    #[must_use]
    pub(crate) fn to_machine_frame(self, contact: Contact) -> Contact {
        contact.offset(-i16::from(self.get()))
    }
}

impl TryFrom<u8> for RotorPosition {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(value)
    }
}

impl From<RotorPosition> for u8 {
    fn from(position: RotorPosition) -> Self {
        position.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fialka::CONTACT_COUNT;

    #[test]
    fn accepts_exact_rotor_position_range() {
        for value in 0..CONTACT_COUNT as u8 {
            assert_eq!(RotorPosition::new(value).map(RotorPosition::get), Some(value));
        }

        assert_eq!(RotorPosition::new(CONTACT_COUNT as u8), None);
    }

    #[test]
    fn base_position_leaves_coordinates_unchanged() {
        for value in 0..CONTACT_COUNT as u8 {
            let contact = Contact::new(value).unwrap();
            let base = RotorPosition::new(0).unwrap();
            assert_eq!(base.to_rotor_frame(contact), contact);
            assert_eq!(base.to_machine_frame(contact), contact);
        }
    }

    #[test]
    fn position_b_aligns_machine_a_with_rotor_b() {
        let a = Contact::new(0).unwrap();
        let b = Contact::new(1).unwrap();
        let position_b = RotorPosition::new(1).unwrap();

        assert_eq!(position_b.to_rotor_frame(a), b);
        assert_eq!(position_b.to_machine_frame(b), a);
    }

    #[test]
    fn coordinate_frame_transforms_cancel_exhaustively() {
        for position in 0..CONTACT_COUNT as u8 {
            let position = RotorPosition::new(position).unwrap();

            for value in 0..CONTACT_COUNT as u8 {
                let contact = Contact::new(value).unwrap();
                assert_eq!(
                    position.to_machine_frame(position.to_rotor_frame(contact)),
                    contact
                );
                assert_eq!(
                    position.to_rotor_frame(position.to_machine_frame(contact)),
                    contact
                );
            }
        }
    }
}
