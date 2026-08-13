//! Polish/Czechoslovak Latin text layer for Fialka M-125-3.
//!
//! The electrical cipher core operates on the same 30 physical key/contact
//! positions regardless of the installed print head. The Polish and
//! Czechoslovak variants use an identical Latin mapping: all 26 Latin letters
//! plus the digits 2, 5, 7 and 8.
//!
//! In canonical Fialka contact order
//!
//!   А Б В Г Д Е Ж З И К Л М Н О П Р С Т У Ф Х Ц Ч Ш Щ Ы Ь Ю Я Й
//!
//! the corresponding Latin-only symbols are
//!
//!   F 7 D U L T 5 P B R K V Z J G H C N E A Q W X I O S M 8 Y 2

use core::fmt;

use crate::Block;

use super::{CONTACT_COUNT, Contact, Fialka};

/// Polish/Czechoslovak Latin symbols indexed by canonical electrical contact.
pub(crate) const LATIN_SYMBOLS: [char; CONTACT_COUNT] = [
    'F', '7', 'D', 'U', 'L', 'T', '5', 'P', 'B', 'R', 'K', 'V', 'Z', 'J', 'G',
    'H', 'C', 'N', 'E', 'A', 'Q', 'W', 'X', 'I', 'O', 'S', 'M', '8', 'Y', '2',
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsupportedLatinSymbol(pub char);

impl fmt::Display for UnsupportedLatinSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "character {:?} is not in the 30-symbol Polish/Czech Fialka Latin alphabet",
            self.0
        )
    }
}

impl std::error::Error for UnsupportedLatinSymbol {}

pub(crate) struct LatinAlphabet;

impl LatinAlphabet {
    pub(crate) fn encode(ch: char) -> Result<Contact, UnsupportedLatinSymbol> {
        let normalized = if ch.is_ascii_lowercase() {
            ch.to_ascii_uppercase()
        } else {
            ch
        };

        let Some(index) = LATIN_SYMBOLS
            .iter()
            .position(|&candidate| candidate == normalized)
        else {
            return Err(UnsupportedLatinSymbol(ch));
        };

        Ok(Contact::new(index as u8).expect("Latin alphabet index is a valid Fialka contact"))
    }

    pub(crate) fn decode(contact: Contact) -> char {
        LATIN_SYMBOLS[contact.get() as usize]
    }
}

impl Fialka {
    /// Encrypt text using the shared Polish/Czechoslovak Latin-only mapping.
    ///
    /// Accepted symbols are A-Z plus 2, 5, 7 and 8. ASCII lower-case letters
    /// are normalized to upper-case.
    pub fn encrypt_latin(&self, src: &str) -> Result<String, UnsupportedLatinSymbol> {
        process_latin(self, src, true)
    }

    /// Decrypt text using the shared Polish/Czechoslovak Latin-only mapping.
    pub fn decrypt_latin(&self, src: &str) -> Result<String, UnsupportedLatinSymbol> {
        process_latin(self, src, false)
    }
}

fn process_latin(
    fialka: &Fialka,
    src: &str,
    encrypt: bool,
) -> Result<String, UnsupportedLatinSymbol> {
    let input: Result<Vec<u8>, UnsupportedLatinSymbol> = src
        .chars()
        .map(|ch| LatinAlphabet::encode(ch).map(Contact::get))
        .collect();
    let input = input?;

    let mut output = vec![0_u8; input.len()];
    let n = if encrypt {
        Block::encrypt(fialka, &mut output, &input)
    } else {
        Block::decrypt(fialka, &mut output, &input)
    };

    debug_assert_eq!(n, input.len());

    let mut text = String::with_capacity(n);
    for raw in output.into_iter().take(n) {
        let contact = Contact::new(raw).expect("Fialka output is always a valid contact");
        text.push(LatinAlphabet::decode(contact));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Commutator, FialkaConfig, RotorSeries};

    #[test]
    fn latin_mapping_contains_thirty_unique_documented_symbols() {
        assert_eq!(LATIN_SYMBOLS.len(), CONTACT_COUNT);

        for (i, symbol) in LATIN_SYMBOLS.iter().enumerate() {
            assert!(!LATIN_SYMBOLS[..i].contains(symbol));
        }

        for letter in 'A'..='Z' {
            assert!(LATIN_SYMBOLS.contains(&letter));
        }
        for digit in ['2', '5', '7', '8'] {
            assert!(LATIN_SYMBOLS.contains(&digit));
        }
    }

    #[test]
    fn published_keyboard_positions_are_reproduced() {
        assert_eq!(LatinAlphabet::decode(Contact::new(0).unwrap()), 'F');  // А
        assert_eq!(LatinAlphabet::decode(Contact::new(1).unwrap()), '7');  // Б
        assert_eq!(LatinAlphabet::decode(Contact::new(6).unwrap()), '5');  // Ж
        assert_eq!(LatinAlphabet::decode(Contact::new(19).unwrap()), 'A'); // Ф
        assert_eq!(LatinAlphabet::decode(Contact::new(21).unwrap()), 'W'); // Ц
        assert_eq!(LatinAlphabet::decode(Contact::new(27).unwrap()), '8'); // Ю
        assert_eq!(LatinAlphabet::decode(Contact::new(29).unwrap()), '2'); // Й
    }

    #[test]
    fn all_latin_symbols_round_trip_through_contacts() {
        for (index, &symbol) in LATIN_SYMBOLS.iter().enumerate() {
            let contact = LatinAlphabet::encode(symbol).unwrap();
            assert_eq!(contact.get() as usize, index);
            assert_eq!(LatinAlphabet::decode(contact), symbol);
        }
    }

    #[test]
    fn lowercase_ascii_is_accepted() {
        for letter in 'a'..='z' {
            assert_eq!(
                LatinAlphabet::encode(letter),
                LatinAlphabet::encode(letter.to_ascii_uppercase())
            );
        }
    }

    #[test]
    fn unsupported_digits_and_punctuation_are_rejected() {
        for ch in ['0', '1', '3', '4', '6', '9', ' ', '.', '-'] {
            assert_eq!(LatinAlphabet::encode(ch), Err(UnsupportedLatinSymbol(ch)));
        }
    }

    #[test]
    fn polish_3k_latin_text_round_trips() {
        let fialka = Fialka::new(FialkaConfig::overall_base(
            RotorSeries::Polish3K,
            Commutator::identity(),
        ));
        let plain = "TAJNE2578";

        let cipher = fialka.encrypt_latin(plain).unwrap();
        let recovered = fialka.decrypt_latin(&cipher).unwrap();

        assert_eq!(recovered, plain);
    }

    #[test]
    fn czechoslovak_6k_latin_text_round_trips_and_normalizes_case() {
        let fialka = Fialka::new(FialkaConfig::overall_base(
            RotorSeries::Czechoslovak6K,
            Commutator::identity(),
        ));
        let plain = "tajnasprava";

        let cipher = fialka.encrypt_latin(plain).unwrap();
        let recovered = fialka.decrypt_latin(&cipher).unwrap();

        assert_eq!(recovered, "TAJNASPRAVA");
    }
}
