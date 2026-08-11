//! Fixed mapping between the Fialka keyboard/print contacts and card reader.
//!
//! The M-125/M-125-3 does not connect the 30 keyboard positions directly to
//! the punched-card commutator.  A fixed substitution sits between them.
//!
//! Sources:
//! - Crypto Museum, "Fialka Wiring":
//!   <https://www.cryptomuseum.com/crypto/fialka/wiring.htm>
//! - H. Hafting's independent Fialka simulator configuration:
//!   <https://github.com/Hafting/enigma/blob/master/fialka-m125>

use super::{CONTACT_COUNT, Contact, Permutation};

/// Published keyboard -> card-reader mapping in the canonical Fialka alphabet.
///
/// Source notation:
///
/// ```text
/// keyboard: А Б В Г Д Е Ж З И К Л М Н О П Р С Т У Ф Х Ц Ч Ш Щ Ы Ь Ю Я Й
/// card:     С Щ Й О Ы Х Е У А П Я Ф Г Ю Ш Б Ц Ч Т М Ж Д Ь З К И Р Н Л В
/// ```
///
/// Values below are zero-based card-reader contacts.
const KEYBOARD_TO_CARD: [u8; CONTACT_COUNT] = [
    16, 24, 29, 13, 25, 20, 5, 18, 0, 14, 28, 19, 3, 27, 23, 1, 21, 22, 17, 11, 6, 4, 26, 7,
    9, 8, 15, 12, 10, 2,
];

/// Fixed keyboard/print-head substitution surrounding the card reader.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KeyboardMapping {
    wiring: Permutation<CONTACT_COUNT>,
}

impl KeyboardMapping {
    /// Construct the historically fixed keyboard mapping.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            wiring: Permutation::new(KEYBOARD_TO_CARD)
                .expect("published Fialka keyboard mapping must be a permutation"),
        }
    }

    /// Traverse from a keyboard/print contact towards the punched-card reader.
    #[must_use]
    pub(crate) fn keyboard_to_card(&self, input: Contact) -> Contact {
        self.wiring.forward_contact(input)
    }

    /// Traverse from the punched-card reader back towards the printer contact.
    #[must_use]
    pub(crate) fn card_to_keyboard(&self, input: Contact) -> Contact {
        self.wiring.inverse_contact(input)
    }
}

impl Default for KeyboardMapping {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALPHABET: [char; CONTACT_COUNT] = [
        'А', 'Б', 'В', 'Г', 'Д', 'Е', 'Ж', 'З', 'И', 'К', 'Л', 'М', 'Н', 'О', 'П', 'Р', 'С', 'Т',
        'У', 'Ф', 'Х', 'Ц', 'Ч', 'Ш', 'Щ', 'Ы', 'Ь', 'Ю', 'Я', 'Й',
    ];

    const PUBLISHED_CARD_SEQUENCE: [char; CONTACT_COUNT] = [
        'С', 'Щ', 'Й', 'О', 'Ы', 'Х', 'Е', 'У', 'А', 'П', 'Я', 'Ф', 'Г', 'Ю', 'Ш', 'Б', 'Ц', 'Ч',
        'Т', 'М', 'Ж', 'Д', 'Ь', 'З', 'К', 'И', 'Р', 'Н', 'Л', 'В',
    ];

    fn contact(value: usize) -> Contact {
        Contact::new(value as u8).unwrap()
    }

    #[test]
    fn published_keyboard_to_card_table_is_transcribed_exactly() {
        let mapping = KeyboardMapping::new();

        for (keyboard_index, expected_card_mark) in PUBLISHED_CARD_SEQUENCE.into_iter().enumerate() {
            let expected_card_index = ALPHABET
                .iter()
                .position(|&mark| mark == expected_card_mark)
                .unwrap();
            assert_eq!(
                mapping.keyboard_to_card(contact(keyboard_index)),
                contact(expected_card_index),
                "keyboard mark {}",
                ALPHABET[keyboard_index]
            );
        }
    }

    #[test]
    fn keyboard_and_return_mapping_cancel_exhaustively() {
        let mapping = KeyboardMapping::new();

        for value in 0..CONTACT_COUNT {
            let input = contact(value);
            assert_eq!(mapping.card_to_keyboard(mapping.keyboard_to_card(input)), input);
            assert_eq!(mapping.keyboard_to_card(mapping.card_to_keyboard(input)), input);
        }
    }

    #[test]
    fn published_mapping_is_not_identity_or_reciprocal() {
        let mapping = KeyboardMapping::new();
        let a = contact(0);
        let s = contact(16);

        assert_eq!(mapping.keyboard_to_card(a), s);
        assert_ne!(mapping.keyboard_to_card(s), a);
    }
}
