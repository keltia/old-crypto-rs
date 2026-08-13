//! Punched-card commutator used by the Fialka M-125-3.
//!
//! The card reader is a programmable 30 x 30 contact matrix.  A key card has
//! one connection for each input/output coordinate and therefore represents a
//! general permutation rather than an Enigma-style set of reciprocal swaps.
//!
//! The signal crosses the card reader twice.  On the way from the keyboard to
//! the rotor drum we apply the programmed permutation; on the return path from
//! the drum to the output encoder we apply its inverse.

use super::{CONTACT_COUNT, Contact, Permutation, PermutationError};

/// Static 30-contact punched-card permutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Commutator {
    wiring: Permutation<CONTACT_COUNT>,
}

impl Commutator {
    /// Construct a commutator from a zero-based 30-contact mapping.
    ///
    /// `mapping[input]` is the drum-side contact reached from the corresponding
    /// keyboard-side contact.  The mapping must contain every value `0..29`
    /// exactly once.
    pub fn new(mapping: [u8; CONTACT_COUNT]) -> Result<Self, PermutationError> {
        Ok(Self {
            wiring: Permutation::new(mapping)?,
        })
    }

    /// The metal Fialka test triangle forces an identity matrix in the card
    /// reader.  Keeping this as a named constructor mirrors the documented
    /// maintenance configuration and is useful for later full-path tests.
    #[must_use]
    pub fn identity() -> Self {
        let mapping = std::array::from_fn(|index| index as u8);
        Self::new(mapping).expect("identity commutator must be a valid permutation")
    }

    /// Traverse the card reader from the keyboard towards the rotor drum.
    #[must_use]
    pub(crate) fn keyboard_to_drum(&self, input: Contact) -> Contact {
        self.wiring.forward_contact(input)
    }

    /// Traverse the card reader from the rotor drum towards the output encoder.
    #[must_use]
    pub(crate) fn drum_to_output(&self, input: Contact) -> Contact {
        self.wiring.inverse_contact(input)
    }

    /// Zero-based keyboard-to-drum mapping, primarily for key-data tests.
    #[must_use]
    pub const fn as_array(&self) -> &[u8; CONTACT_COUNT] {
        self.wiring.as_array()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contact(value: u8) -> Contact {
        Contact::new(value).unwrap()
    }

    #[test]
    fn identity_matches_the_documented_test_triangle() {
        let card = Commutator::identity();

        for value in 0..CONTACT_COUNT as u8 {
            let input = contact(value);
            assert_eq!(card.keyboard_to_drum(input), input);
            assert_eq!(card.drum_to_output(input), input);
        }
    }

    #[test]
    fn accepts_a_general_non_reciprocal_permutation() {
        // A one-position 30-cycle is deliberately not self-reciprocal.  It
        // demonstrates why the return traversal must use the inverse mapping.
        let mapping = std::array::from_fn(|index| ((index + 1) % CONTACT_COUNT) as u8);
        let card = Commutator::new(mapping).unwrap();

        assert_eq!(card.keyboard_to_drum(contact(0)), contact(1));
        assert_eq!(card.keyboard_to_drum(contact(29)), contact(0));

        assert_eq!(card.drum_to_output(contact(1)), contact(0));
        assert_eq!(card.drum_to_output(contact(0)), contact(29));

        // In particular, applying the same direction twice is not an inverse.
        assert_eq!(card.keyboard_to_drum(contact(1)), contact(2));
        assert_ne!(card.keyboard_to_drum(contact(1)), contact(0));
    }

    #[test]
    fn both_traversal_directions_cancel_exhaustively() {
        // Multiplication by 7 modulo 30 is a permutation because gcd(7, 30)=1.
        let mapping = std::array::from_fn(|index| ((index * 7) % CONTACT_COUNT) as u8);
        let card = Commutator::new(mapping).unwrap();

        for value in 0..CONTACT_COUNT as u8 {
            let input = contact(value);
            assert_eq!(card.drum_to_output(card.keyboard_to_drum(input)), input);
            assert_eq!(card.keyboard_to_drum(card.drum_to_output(input)), input);
        }
    }

    #[test]
    fn constructor_rejects_duplicate_card_connections() {
        let mut mapping = std::array::from_fn(|index| index as u8);
        mapping[29] = 28;

        assert!(matches!(
            Commutator::new(mapping),
            Err(PermutationError::Duplicate {
                value: 28,
                first_index: 28,
                second_index: 29,
            })
        ));
    }

    #[test]
    fn constructor_rejects_out_of_range_card_connections() {
        let mut mapping = std::array::from_fn(|index| index as u8);
        mapping[17] = 30;

        assert!(matches!(
            Commutator::new(mapping),
            Err(PermutationError::OutOfRange {
                index: 17,
                value: 30,
                size: CONTACT_COUNT,
            })
        ));
    }

    #[test]
    fn preserves_the_original_validated_mapping() {
        let mapping = std::array::from_fn(|index| ((index * 11) % CONTACT_COUNT) as u8);
        let card = Commutator::new(mapping).unwrap();

        assert_eq!(card.as_array(), &mapping);
    }
}
