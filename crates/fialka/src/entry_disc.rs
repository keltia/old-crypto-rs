//! Fixed entry disc between the punched-card commutator and rotor 10.
//!
//! The Fialka Reference Manual publishes the complete 30-contact entry-disc
//! wiring.  Historical contact numbers are one-based; this module stores the
//! transcription in that form and converts it to the crate's zero-based
//! [`Contact`] coordinate system when constructing the validated permutation.

use super::{CONTACT_COUNT, Contact, Permutation};

/// Published entry-disc wiring, card-reader side -> rotor-drum side.
///
/// Values are preserved exactly as historical one-based contact numbers to
/// make comparison with the Reference Manual straightforward.
const ENTRY_DISC_ONE_BASED: [u8; CONTACT_COUNT] = [
    28, 14, 20, 24, 2, 16, 1, 10, 21, 11, 17, 13, 19, 30, 5, 6, 8, 15, 23, 25, 27, 18, 3, 29,
    26, 12, 22, 7, 9, 4,
];

/// Static 30-contact entry disc.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EntryDisc {
    wiring: Permutation<CONTACT_COUNT>,
}

impl EntryDisc {
    /// Construct the documented fixed entry disc.
    #[must_use]
    pub(crate) fn new() -> Self {
        let zero_based = ENTRY_DISC_ONE_BASED.map(|value| value - 1);
        Self {
            wiring: Permutation::new(zero_based)
                .expect("published Fialka entry-disc wiring must be a permutation"),
        }
    }

    /// Traverse from the card reader towards rotor 10.
    #[must_use]
    pub(crate) fn card_to_drum(&self, input: Contact) -> Contact {
        self.wiring.forward_contact(input)
    }

    /// Traverse from rotor 10 back towards the card reader.
    #[must_use]
    pub(crate) fn drum_to_card(&self, input: Contact) -> Contact {
        self.wiring.inverse_contact(input)
    }

    /// Zero-based card-reader -> drum mapping, primarily for reference tests.
    #[must_use]
    pub(crate) const fn as_array(&self) -> &[u8; CONTACT_COUNT] {
        self.wiring.as_array()
    }
}

impl Default for EntryDisc {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contact(one_based: u8) -> Contact {
        Contact::new(one_based - 1).unwrap()
    }

    #[test]
    fn wiring_matches_the_reference_manual_exactly() {
        let entry = EntryDisc::new();
        let expected = ENTRY_DISC_ONE_BASED.map(|value| value - 1);
        assert_eq!(entry.as_array(), &expected);

        // A few deliberately scattered one-based source checks.
        assert_eq!(entry.card_to_drum(contact(1)), contact(28));
        assert_eq!(entry.card_to_drum(contact(7)), contact(1));
        assert_eq!(entry.card_to_drum(contact(14)), contact(30));
        assert_eq!(entry.card_to_drum(contact(23)), contact(3));
        assert_eq!(entry.card_to_drum(contact(30)), contact(4));
    }

    #[test]
    fn both_directions_cancel_for_all_contacts() {
        let entry = EntryDisc::new();

        for value in 0..CONTACT_COUNT as u8 {
            let input = Contact::new(value).unwrap();
            assert_eq!(entry.drum_to_card(entry.card_to_drum(input)), input);
            assert_eq!(entry.card_to_drum(entry.drum_to_card(input)), input);
        }
    }
}
