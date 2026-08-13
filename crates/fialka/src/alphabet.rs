//! Russian text/alphabet layer for Fialka M-125-3M.
//!
//! The cipher engine itself operates exclusively on 30 electrical contacts.  This
//! module is the first presentation layer above that engine: it defines the
//! 30-letter Russian alphabet used by Fialka and models the machine's three text
//! modes without teaching rotors, the commutator, or the reflector about Unicode.
//!
//! Sources:
//! - https://www.cryptomuseum.com/crypto/fialka/m125_3/rus.htm
//! - https://www.cryptomuseum.com/crypto/fialka/m125_3/
//!
//! The Russian M-125-3M supports three text modes: letters-only, mixed, and
//! numbers-only.  In mixed mode the physical keys that produce Ф and Ж in
//! letters-only mode become the ЦФ (figures) and БК (letters) shift keys.
//!
//! The exact figures-register glyph table and the special 30->10 numerical
//! reduction path are intentionally *not* guessed here.  Until those tables are
//! transcribed from a primary/curated source, figure and numerical contacts are
//! represented losslessly as contacts.

use core::fmt;

use super::{CONTACT_COUNT, Contact};

/// The 30 Cyrillic letters supported by Fialka, in the machine's canonical
/// electrical/contact order.
///
/// Russian has 33 modern letters; Fialka omits Ё, Ъ and Э.
pub(crate) const RUSSIAN_LETTERS: [char; CONTACT_COUNT] = [
    'А', 'Б', 'В', 'Г', 'Д', 'Е', 'Ж', 'З', 'И', 'К', 'Л', 'М', 'Н', 'О', 'П',
    'Р', 'С', 'Т', 'У', 'Ф', 'Х', 'Ц', 'Ч', 'Ш', 'Щ', 'Ы', 'Ь', 'Ю', 'Я', 'Й',
];

/// The operator-selectable text mode of an M-125-3M.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TextMode {
    /// Б — Буквы: all 30 contacts are Cyrillic letters.
    Letters,
    /// С — Смешанные: letters and figures share the keyboard via shift keys.
    Mixed,
    /// Ц — Цифры: numerical operation; the 30->10 reduction is a later layer.
    Numbers,
}

/// Active register while the machine is in mixed text mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MixedRegister {
    Letters,
    Figures,
}

/// Result of interpreting one contact through the Russian text-mode layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RussianSymbol {
    Letter(char),
    ShiftToFigures,
    ShiftToLetters,
    /// A figures-register symbol whose printable glyph has deliberately not yet
    /// been assigned by this implementation.
    Figure(Contact),
    /// A contact entering the numbers-only 30->10 mechanism.
    Numeric(Contact),
}

/// Error returned when a Unicode character is not part of Fialka's 30-letter
/// Russian alphabet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsupportedRussianLetter(pub char);

impl fmt::Display for UnsupportedRussianLetter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "character {:?} is not in the 30-letter Fialka Russian alphabet", self.0)
    }
}

impl std::error::Error for UnsupportedRussianLetter {}

/// Stateless conversion between Russian letters and the 30-contact coordinate.
pub(crate) struct RussianAlphabet;

impl RussianAlphabet {
    /// Encode one Russian letter. Lower-case input is accepted and normalized.
    pub(crate) fn encode(ch: char) -> Result<Contact, UnsupportedRussianLetter> {
        let upper = ch.to_uppercase().next().unwrap_or(ch);
        let Some(index) = RUSSIAN_LETTERS.iter().position(|&candidate| candidate == upper) else {
            return Err(UnsupportedRussianLetter(ch));
        };

        // SAFETY is not needed: index is bounded by the 30-element source array.
        Ok(Contact::new(index as u8).expect("Russian alphabet index is a valid contact"))
    }

    /// Decode one contact as its letters-only Cyrillic glyph.
    pub(crate) fn decode(contact: Contact) -> char {
        RUSSIAN_LETTERS[contact.get() as usize]
    }

    pub(crate) fn figures_shift_contact() -> Contact {
        Self::encode('Ф').expect("Ф is part of the Fialka alphabet")
    }

    pub(crate) fn letters_shift_contact() -> Contact {
        Self::encode('Ж').expect("Ж is part of the Fialka alphabet")
    }
}

/// Stateful interpretation of contacts according to the selected text mode.
///
/// Cipher/decipher mode is deliberately separate; this type models only the
/// Б/С/Ц text selector and mixed-mode register state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RussianTextState {
    mode: TextMode,
    register: MixedRegister,
}

impl RussianTextState {
    pub(crate) const fn new(mode: TextMode) -> Self {
        Self {
            mode,
            register: MixedRegister::Letters,
        }
    }

    pub(crate) const fn mode(self) -> TextMode {
        self.mode
    }

    pub(crate) const fn register(self) -> MixedRegister {
        self.register
    }

    pub(crate) fn set_mode(&mut self, mode: TextMode) {
        self.mode = mode;
        // Entering mixed mode starts from the letters register. This also makes
        // mode changes deterministic for a simulator/API caller.
        self.register = MixedRegister::Letters;
    }

    /// Interpret one machine contact and update mixed-register state if it is a
    /// shift control.
    pub(crate) fn consume(&mut self, contact: Contact) -> RussianSymbol {
        match self.mode {
            TextMode::Letters => RussianSymbol::Letter(RussianAlphabet::decode(contact)),
            TextMode::Numbers => RussianSymbol::Numeric(contact),
            TextMode::Mixed => self.consume_mixed(contact),
        }
    }

    fn consume_mixed(&mut self, contact: Contact) -> RussianSymbol {
        if contact == RussianAlphabet::figures_shift_contact() {
            self.register = MixedRegister::Figures;
            return RussianSymbol::ShiftToFigures;
        }
        if contact == RussianAlphabet::letters_shift_contact() {
            self.register = MixedRegister::Letters;
            return RussianSymbol::ShiftToLetters;
        }

        match self.register {
            MixedRegister::Letters => RussianSymbol::Letter(RussianAlphabet::decode(contact)),
            MixedRegister::Figures => RussianSymbol::Figure(contact),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn russian_alphabet_has_exactly_thirty_unique_letters() {
        assert_eq!(RUSSIAN_LETTERS.len(), CONTACT_COUNT);
        for (i, letter) in RUSSIAN_LETTERS.iter().enumerate() {
            assert!(!RUSSIAN_LETTERS[..i].contains(letter));
        }
    }

    #[test]
    fn all_letters_round_trip_through_contacts() {
        for (index, &letter) in RUSSIAN_LETTERS.iter().enumerate() {
            let contact = RussianAlphabet::encode(letter).unwrap();
            assert_eq!(contact.get() as usize, index);
            assert_eq!(RussianAlphabet::decode(contact), letter);
        }
    }

    #[test]
    fn lowercase_input_is_accepted() {
        for &letter in &RUSSIAN_LETTERS {
            let lower = letter.to_lowercase().next().unwrap();
            assert_eq!(RussianAlphabet::encode(lower), RussianAlphabet::encode(letter));
        }
    }

    #[test]
    fn omitted_modern_russian_letters_are_rejected() {
        for letter in ['Ё', 'Ъ', 'Э', 'ё', 'ъ', 'э'] {
            assert_eq!(
                RussianAlphabet::encode(letter),
                Err(UnsupportedRussianLetter(letter))
            );
        }
    }

    #[test]
    fn letters_mode_interprets_all_contacts_as_letters() {
        let mut state = RussianTextState::new(TextMode::Letters);
        for raw in 0..CONTACT_COUNT as u8 {
            let contact = Contact::new(raw).unwrap();
            assert_eq!(
                state.consume(contact),
                RussianSymbol::Letter(RussianAlphabet::decode(contact))
            );
        }
    }

    #[test]
    fn mixed_mode_uses_f_and_zh_keys_as_shift_controls() {
        let mut state = RussianTextState::new(TextMode::Mixed);
        let figures = RussianAlphabet::encode('Ф').unwrap();
        let letters = RussianAlphabet::encode('Ж').unwrap();
        let a = RussianAlphabet::encode('А').unwrap();

        assert_eq!(state.register(), MixedRegister::Letters);
        assert_eq!(state.consume(a), RussianSymbol::Letter('А'));

        assert_eq!(state.consume(figures), RussianSymbol::ShiftToFigures);
        assert_eq!(state.register(), MixedRegister::Figures);
        assert_eq!(state.consume(a), RussianSymbol::Figure(a));

        assert_eq!(state.consume(letters), RussianSymbol::ShiftToLetters);
        assert_eq!(state.register(), MixedRegister::Letters);
        assert_eq!(state.consume(a), RussianSymbol::Letter('А'));
    }

    #[test]
    fn numbers_mode_preserves_contacts_for_later_30_to_10_reduction() {
        let mut state = RussianTextState::new(TextMode::Numbers);
        for raw in 0..CONTACT_COUNT as u8 {
            let contact = Contact::new(raw).unwrap();
            assert_eq!(state.consume(contact), RussianSymbol::Numeric(contact));
        }
    }

    #[test]
    fn changing_text_mode_resets_mixed_register_to_letters() {
        let mut state = RussianTextState::new(TextMode::Mixed);
        state.consume(RussianAlphabet::figures_shift_contact());
        assert_eq!(state.register(), MixedRegister::Figures);

        state.set_mode(TextMode::Numbers);
        assert_eq!(state.mode(), TextMode::Numbers);
        assert_eq!(state.register(), MixedRegister::Letters);

        state.set_mode(TextMode::Mixed);
        assert_eq!(state.register(), MixedRegister::Letters);
    }
}
