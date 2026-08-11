//! Electrical model of a Fialka rotor in its documented base position.
//!
//! Rotor motion, ring settings, and PROTON-2 core adjustments are deliberately
//! kept out of this type.  At this stage a rotor is only a named 30-contact
//! electrical permutation.

use super::{Contact, Permutation, PermutationError, RotorPosition};

/// Identity of one of the ten Fialka rotor wirings.
///
/// The variants transliterate the first ten letters used to mark Fialka
/// rotors: А, Б, В, Г, Д, Е, Ж, З, И, К.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RotorId {
    A,
    B,
    V,
    G,
    D,
    E,
    Zh,
    Z,
    I,
    K,
}

impl RotorId {
    /// All ten rotor identities in the historical table order А .. К.
    pub const ALL: [Self; 10] = [
        Self::A,
        Self::B,
        Self::V,
        Self::G,
        Self::D,
        Self::E,
        Self::Zh,
        Self::Z,
        Self::I,
        Self::K,
    ];

    /// Zero-based column in published Fialka rotor tables.
    #[must_use]
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::A => 0,
            Self::B => 1,
            Self::V => 2,
            Self::G => 3,
            Self::D => 4,
            Self::E => 5,
            Self::Zh => 6,
            Self::Z => 7,
            Self::I => 8,
            Self::K => 9,
        }
    }
}

/// Fixed electrical wiring of one Fialka rotor.
///
/// Published Fialka wiring tables define the transform from the spring-loaded
/// contacts on the **right** face to the flat contacts on the **left** face.
/// Consequently `right_to_left()` applies the published permutation directly,
/// while `left_to_right()` applies its inverse.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RotorCore {
    id: RotorId,
    wiring: Permutation<30>,
}

impl RotorCore {
    /// Construct and validate a rotor wiring.
    pub(crate) fn new(id: RotorId, wiring: [u8; 30]) -> Result<Self, PermutationError> {
        Ok(Self {
            id,
            wiring: Permutation::new(wiring)?,
        })
    }

    /// Return the historical identity of this rotor wiring.
    #[must_use]
    pub(crate) const fn id(&self) -> RotorId {
        self.id
    }

    /// Pass a signal from the input/right face to the output/left face.
    #[must_use]
    pub(crate) fn right_to_left(&self, input: Contact) -> Contact {
        self.wiring.forward_contact(input)
    }

    /// Pass a signal from the output/left face back to the input/right face.
    #[must_use]
    pub(crate) fn left_to_right(&self, input: Contact) -> Contact {
        self.wiring.inverse_contact(input)
    }

    /// Right-to-left transform when this removable core is physically flipped
    /// so that side 2 is visible from the left side of the assembled wheel.
    ///
    /// Flipping exchanges the two electrical faces and mirrors angular contact
    /// coordinates about the white core-index mark.  With `R(x) = -x mod 30`,
    /// this is `R * P^-1 * R`.
    #[must_use]
    pub(crate) fn mirrored_right_to_left(&self, input: Contact) -> Contact {
        reflect_contact(self.left_to_right(reflect_contact(input)))
    }

    /// Left-to-right inverse of [`RotorCore::mirrored_right_to_left`].
    #[must_use]
    pub(crate) fn mirrored_left_to_right(&self, input: Contact) -> Contact {
        reflect_contact(self.right_to_left(reflect_contact(input)))
    }
}

/// Reflect a rotor-local coordinate about the core's white index mark.
///
/// Contact zero lies on the reflection axis and therefore remains zero; the
/// remaining contacts reverse order (`1 <-> 29`, `2 <-> 28`, ...).
fn reflect_contact(contact: Contact) -> Contact {
    Contact::new(0)
        .expect("contact zero is valid")
        .offset(-i16::from(contact.get()))
}

/// A fixed-wiring rotor mounted at a particular angular position.
///
/// This type models only the static electrical effect of rotor rotation.  It
/// deliberately contains no stepping direction, blocking pins, ring setting,
/// or PROTON-2 core adjustment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PositionedRotor {
    core: RotorCore,
    position: RotorPosition,
}

impl PositionedRotor {
    /// Mount a rotor core at a fixed angular position.
    #[must_use]
    pub(crate) fn new(core: RotorCore, position: RotorPosition) -> Self {
        Self { core, position }
    }

    /// Rotor wiring identity.
    #[must_use]
    pub(crate) const fn id(&self) -> RotorId {
        self.core.id()
    }

    /// Current static rotor position.
    #[must_use]
    pub(crate) const fn position(&self) -> RotorPosition {
        self.position
    }

    /// Change the static rotor position.
    pub(crate) fn set_position(&mut self, position: RotorPosition) {
        self.position = position;
    }

    /// Pass a signal from the machine's right side to its left side.
    ///
    /// The fixed machine contact is first expressed in the rotated rotor's
    /// local coordinate frame, passed through the published right-to-left
    /// wiring, then converted back to the fixed machine frame.
    #[must_use]
    pub(crate) fn right_to_left(&self, input: Contact) -> Contact {
        let local_input = self.position.to_rotor_frame(input);
        let local_output = self.core.right_to_left(local_input);
        self.position.to_machine_frame(local_output)
    }

    /// Pass a signal from the machine's left side back to its right side.
    #[must_use]
    pub(crate) fn left_to_right(&self, input: Contact) -> Contact {
        let local_input = self.position.to_rotor_frame(input);
        let local_output = self.core.left_to_right(local_input);
        self.position.to_machine_frame(local_output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotor_ids_have_stable_table_indices() {
        for (index, id) in RotorId::ALL.into_iter().enumerate() {
            assert_eq!(id.index(), index);
        }
    }

    #[test]
    fn electrical_directions_are_exact_inverses() {
        // A deliberately non-trivial valid permutation. Historical data is
        // tested independently in data::polish below.
        let wiring = std::array::from_fn(|index| ((index * 7) % 30) as u8);
        let rotor = RotorCore::new(RotorId::A, wiring).unwrap();

        for value in 0..30 {
            let contact = Contact::new(value).unwrap();
            assert_eq!(rotor.left_to_right(rotor.right_to_left(contact)), contact);
            assert_eq!(rotor.right_to_left(rotor.left_to_right(contact)), contact);
        }
    }

    #[test]
    fn contact_reflection_keeps_index_mark_and_reverses_the_circle() {
        assert_eq!(reflect_contact(Contact::new(0).unwrap()), Contact::new(0).unwrap());
        for value in 1..30 {
            assert_eq!(
                reflect_contact(Contact::new(value).unwrap()),
                Contact::new(30 - value).unwrap()
            );
        }
    }

    #[test]
    fn mirrored_core_directions_are_exact_inverses() {
        // An affine permutation makes the reflection observable rather than
        // accidentally collapsing to the ordinary inverse transform.
        let wiring = std::array::from_fn(|index| ((index * 7 + 3) % 30) as u8);
        let rotor = RotorCore::new(RotorId::A, wiring).unwrap();

        for value in 0..30 {
            let contact = Contact::new(value).unwrap();
            assert_eq!(
                rotor.mirrored_left_to_right(rotor.mirrored_right_to_left(contact)),
                contact
            );
            assert_eq!(
                rotor.mirrored_right_to_left(rotor.mirrored_left_to_right(contact)),
                contact
            );
        }

        // M = R * P^-1 * R. For P(x) = 7x + 3 (mod 30), P^-1(x) =
        // 13(x - 3), hence M(0) = 9.
        assert_eq!(
            rotor.mirrored_right_to_left(Contact::new(0).unwrap()),
            Contact::new(9).unwrap()
        );
    }

    #[test]
    fn positioned_rotor_at_a_matches_bare_core() {
        let wiring = std::array::from_fn(|index| ((index * 7) % 30) as u8);
        let core = RotorCore::new(RotorId::A, wiring).unwrap();
        let rotor = PositionedRotor::new(core.clone(), RotorPosition::new(0).unwrap());

        for value in 0..30 {
            let contact = Contact::new(value).unwrap();
            assert_eq!(rotor.right_to_left(contact), core.right_to_left(contact));
            assert_eq!(rotor.left_to_right(contact), core.left_to_right(contact));
        }
    }

    #[test]
    fn positioned_rotor_directions_cancel_at_all_positions() {
        let wiring = std::array::from_fn(|index| ((index * 7) % 30) as u8);
        let core = RotorCore::new(RotorId::A, wiring).unwrap();

        for position in 0..30 {
            let rotor = PositionedRotor::new(core.clone(), RotorPosition::new(position).unwrap());

            for value in 0..30 {
                let contact = Contact::new(value).unwrap();
                assert_eq!(rotor.left_to_right(rotor.right_to_left(contact)), contact);
                assert_eq!(rotor.right_to_left(rotor.left_to_right(contact)), contact);
            }
        }
    }

    #[test]
    fn changing_position_changes_coordinate_alignment_not_wiring() {
        // With P(x) = 7x (mod 30), position Б (1) gives
        // P_positioned(А) = P(Б) - 1 = З(7) - 1 = Ж(6).
        let wiring = std::array::from_fn(|index| ((index * 7) % 30) as u8);
        let core = RotorCore::new(RotorId::A, wiring).unwrap();
        let rotor = PositionedRotor::new(core, RotorPosition::new(1).unwrap());
        let a = Contact::new(0).unwrap();
        let zh = Contact::new(6).unwrap();

        assert_eq!(rotor.right_to_left(a), zh);
    }
}
