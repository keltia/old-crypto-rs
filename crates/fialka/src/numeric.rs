//! M-125-3 `30 <-> 10` numbers-only reduction circuit.
//!
//! In position `10`, the NumLock switch disconnects twenty keyboard lines.
//! Each of those twenty card-reader contacts is connected instead to one of
//! the twenty exported reflector contacts. The connection is bidirectional.
//!
//! This creates two possible re-entry loops during one keypress:
//!
//! 1. Forward traversal: exported reflector contact -> switched card input.
//! 2. Reverse traversal: switched card output -> exported reflector contact.
//!
//! The signal becomes printable only when the reverse path reaches one of the
//! ten card contacts still wired directly to the coloured number keys.
//! The rotor drum remains stationary for all internal passes and steps once
//! after the complete keypress.
//!
//! Source: Paul Reuvers & Marc Simons, The Fialka M-125 Reference Manual,
//! v2.0, section 4.8, pp.110-112.

use core::fmt;

use super::{CONTACT_COUNT, Contact};

/// Reflector contact -> card-reader contact in NumLock `10` mode.
///
/// Source numbering is one-based; stored values are zero-based.
/// `None` denotes one of the ten terminal reflector contacts.
const REFLECTOR_TO_CARD: [Option<u8>; CONTACT_COUNT] = [
    Some(9),  //  1 -> 10
    Some(28), //  2 -> 29
    Some(8),  //  3 ->  9
    Some(2),  //  4 ->  3
    Some(27), //  5 -> 28
    Some(20), //  6 -> 21
    Some(21), //  7 -> 22
    Some(15), //  8 -> 16
    None,     //  9 -> 22 fixed reflector loop
    None,     // 10 -> 11 fixed reflector loop
    None,     // 11 -> 10 fixed reflector loop
    Some(12), // 12 -> 13
    None,     // 13 -> plaintext-enable
    Some(0),  // 14 ->  1
    Some(19), // 15 -> 20
    None,     // 16 -> Magic Circuit
    Some(4),  // 17 ->  5
    None,     // 18 -> Magic Circuit
    Some(29), // 19 -> 30
    Some(25), // 20 -> 26
    Some(5),  // 21 ->  6
    None,     // 22 ->  9 fixed reflector loop
    Some(18), // 23 -> 19
    None,     // 24 -> Magic Circuit
    Some(14), // 25 -> 15
    None,     // 26 -> 30 fixed reflector loop
    Some(11), // 27 -> 12
    Some(26), // 28 -> 27
    Some(10), // 29 -> 11
    None,     // 30 -> 26 fixed reflector loop
];

/// Physical keyboard contacts used for decimal digits.
///
/// digit:    0  1  2  3  4  5  6  7  8  9
/// key:      Х  Ш  У  Г  Н  А  Т  Р  Б  П
/// contact: 21 24 19  4 13  1 18 16  2 15   (one-based)
const DIGIT_TO_CONTACT: [u8; 10] = [
    20, // 0 -> Х
    23, // 1 -> Ш
    18, // 2 -> У
    3,  // 3 -> Г
    12, // 4 -> Н
    0,  // 5 -> А
    17, // 6 -> Т
    15, // 7 -> Р
    1,  // 8 -> Б
    14, // 9 -> П
];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ReductionSwitch;

impl ReductionSwitch {
    #[must_use]
    pub(crate) fn card_input(reflector: Contact) -> Option<Contact> {
        REFLECTOR_TO_CARD[usize::from(reflector.get())]
            .map(|value| Contact::new(value).expect("published card input is in 0..30"))
    }

    #[must_use]
    pub(crate) fn reflector_contact(card_input: Contact) -> Option<Contact> {
        let raw = card_input.get();

        REFLECTOR_TO_CARD
            .iter()
            .position(|&candidate| candidate == Some(raw))
            .map(|index| {
                Contact::new(index as u8).expect("reflector table index is a valid contact")
            })
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn is_terminal_reflector(reflector: Contact) -> bool {
        Self::card_input(reflector).is_none()
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn is_direct_card_input(card_input: Contact) -> bool {
        Self::reflector_contact(card_input).is_none()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NumericModeError {
    UnsupportedCharacter(char),
    ReductionCycle {
        reflector_contact: u8,
    },
    NonNumericOutput {
        contact: u8,
    },
}

impl fmt::Display for NumericModeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::UnsupportedCharacter(ch) => {
                write!(f, "character {ch:?} is not a decimal digit accepted by Fialka NumLock")
            }
            Self::ReductionCycle {
                reflector_contact,
            } => write!(
                f,
                "Fialka NumLock reduction entered a cycle at reflector contact {reflector_contact}"
            ),
            Self::NonNumericOutput { contact } => write!(
                f,
                "Fialka NumLock produced non-numeric keyboard contact {contact}"
            ),
        }
    }
}

impl std::error::Error for NumericModeError {}

pub(crate) struct NumericAlphabet;

impl NumericAlphabet {
    pub(crate) fn encode(ch: char) -> Result<Contact, NumericModeError> {
        let digit = ch
            .to_digit(10)
            .filter(|_| ch.is_ascii_digit())
            .ok_or(NumericModeError::UnsupportedCharacter(ch))? as usize;

        Contact::new(DIGIT_TO_CONTACT[digit])
            .ok_or(NumericModeError::UnsupportedCharacter(ch))
    }

    pub(crate) fn decode(contact: Contact) -> Result<char, NumericModeError> {
        let Some(digit) = DIGIT_TO_CONTACT
            .iter()
            .position(|&candidate| candidate == contact.get())
        else {
            return Err(NumericModeError::NonNumericOutput {
                contact: contact.get() + 1,
            });
        };

        Ok(char::from(b'0' + digit as u8))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(value: u8) -> Contact {
        Contact::new(value - 1).unwrap()
    }

    #[test]
    fn all_twenty_published_connections_are_exact_and_bidirectional() {
        const EXPECTED: [(u8, u8); 20] = [
            (1, 10), (2, 29), (3, 9), (4, 3), (5, 28),
            (6, 21), (7, 22), (8, 16), (12, 13), (14, 1),
            (15, 20), (17, 5), (19, 30), (20, 26), (21, 6),
            (23, 19), (25, 15), (27, 12), (28, 27), (29, 11),
        ];

        for (reflector, card) in EXPECTED {
            assert_eq!(ReductionSwitch::card_input(c(reflector)), Some(c(card)));
            assert_eq!(ReductionSwitch::reflector_contact(c(card)), Some(c(reflector)));
        }
    }

    #[test]
    fn ten_reflector_contacts_are_terminal() {
        const TERMINAL: [u8; 10] = [9, 10, 11, 13, 16, 18, 22, 24, 26, 30];

        let actual: Vec<_> = (1..=30)
            .filter(|&n| ReductionSwitch::is_terminal_reflector(c(n)))
            .collect();

        assert_eq!(actual, TERMINAL);
    }

    #[test]
    fn ten_card_contacts_are_direct_to_keyboard() {
        let direct: Vec<_> = (1..=30)
            .filter(|&n| ReductionSwitch::is_direct_card_input(c(n)))
            .collect();

        assert_eq!(direct.len(), 10);
    }

    #[test]
    fn decimal_digit_contacts_match_the_published_keyboard() {
        const EXPECTED: [u8; 10] = [21, 24, 19, 4, 13, 1, 18, 16, 2, 15];

        for (digit, expected) in EXPECTED.into_iter().enumerate() {
            let ch = char::from(b'0' + digit as u8);
            assert_eq!(NumericAlphabet::encode(ch).unwrap(), c(expected));
            assert_eq!(NumericAlphabet::decode(c(expected)).unwrap(), ch);
        }
    }
}
