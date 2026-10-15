//! Frozen electrical path through PURPLE's daily alphabet and switch banks.
//!
//! Switch positions are fixed for each call. This type deliberately has no
//! stepping or message state; the stateful machine will compose it in Step 10.
//!
//! Freeman, Sullivan & Weierud, *PURPLE Revealed* (2003), pp. 8 and 26:
//! https://cryptocellar.org/pubs/purple-revealed.pdf
//! Deciphering the twenties traverses physical switches #3 -> #2 -> #1.

use crate::{
    AlphabetContact, AlphabetError, PurpleAlphabet, SixesSwitch, SwitchPosition,
    TwentiesSwitch, TwentiesSwitchId,
};

/// Electrical transformation at fixed historical switch positions.
pub struct PurpleCore {
    alphabet: PurpleAlphabet,
    sixes: SixesSwitch,
    twenties: [TwentiesSwitch; 3],
}

impl PurpleCore {
    /// The three twenties positions are in physical order (#1, #2, #3).
    pub fn new(
        alphabet: PurpleAlphabet,
        sixes: SwitchPosition,
        twenties: [SwitchPosition; 3],
    ) -> Self {
        use TwentiesSwitchId::{One, Two, Three};
        Self {
            alphabet,
            sixes: SixesSwitch::new(sixes),
            twenties: [
                TwentiesSwitch::new(One, twenties[0]),
                TwentiesSwitch::new(Two, twenties[1]),
                TwentiesSwitch::new(Three, twenties[2]),
            ],
        }
    }

    /// Daily alphabet, in sixes-then-twenties contact order.
    pub fn alphabet(&self) -> &PurpleAlphabet { &self.alphabet }

    /// Current sixes position (the core does not advance it).
    pub fn sixes_position(&self) -> SwitchPosition { self.sixes.position() }

    /// Current twenties positions in physical order (#1, #2, #3).
    pub fn twenties_positions(&self) -> [SwitchPosition; 3] {
        self.twenties.each_ref().map(TwentiesSwitch::position)
    }

    /// Set all four stationary switch positions without processing a letter.
    pub fn set_positions(&mut self, sixes: SwitchPosition, twenties: [SwitchPosition; 3]) {
        self.sixes.set_position(sixes);
        for (switch, position) in self.twenties.iter_mut().zip(twenties) {
            switch.set_position(position);
        }
    }

    /// Decipher one uppercase ASCII letter; no switch advances.
    pub fn decipher(&self, letter: u8) -> Result<u8, AlphabetError> {
        let contact = match self.alphabet.contact(letter)? {
            AlphabetContact::Sixes(c) => AlphabetContact::Sixes(self.sixes.decipher(c)),
            AlphabetContact::Twenties(c) => {
                let c = self.twenties[2].decipher(c);
                let c = self.twenties[1].decipher(c);
                AlphabetContact::Twenties(self.twenties[0].decipher(c))
            }
        };
        Ok(self.alphabet.letter(contact))
    }

    /// Encipher one uppercase ASCII letter using the inverse electrical path.
    pub fn encipher(&self, letter: u8) -> Result<u8, AlphabetError> {
        let contact = match self.alphabet.contact(letter)? {
            AlphabetContact::Sixes(c) => AlphabetContact::Sixes(self.sixes.encipher(c)),
            AlphabetContact::Twenties(c) => {
                let c = self.twenties[0].encipher(c);
                let c = self.twenties[1].encipher(c);
                AlphabetContact::Twenties(self.twenties[2].encipher(c))
            }
        };
        Ok(self.alphabet.letter(contact))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AlphabetError;

    fn p(n: u8) -> SwitchPosition { SwitchPosition::new(n).unwrap() }

    #[test]
    fn december_1941_first_letter_deciphers_without_stepping() {
        // PURPLE Revealed, pp. 25-26: ZTX -> FOV, first letter Z -> F.
        let core = PurpleCore::new(
            PurpleAlphabet::new("NOKTYUXEQLHBRMPDICJASVWGZF").unwrap(),
            p(9), [p(1), p(24), p(6)],
        );
        assert_eq!(core.decipher(b'Z'), Ok(b'F'));
        assert_eq!(core.encipher(b'F'), Ok(b'Z'));
        assert_eq!(core.twenties_positions().map(SwitchPosition::number), [1, 24, 6]);
        assert_eq!(core.sixes_position().number(), 9);
    }

    #[test]
    fn exhaustive_round_trips_and_bank_partition() {
        for alphabet in [PurpleAlphabet::default(),
                         PurpleAlphabet::new("NOKTYUXEQLHBRMPDICJASVWGZF").unwrap()] {
            for six in [1, 9, 25] {
                for positions in [[1, 1, 1], [1, 24, 6], [25, 20, 13]] {
                    let core = PurpleCore::new(alphabet.clone(), p(six), positions.map(p));
                    for letter in b'A'..=b'Z' {
                        let decrypted = core.decipher(letter).unwrap();
                        let encrypted = core.encipher(letter).unwrap();
                        assert_eq!(core.encipher(decrypted), Ok(letter));
                        assert_eq!(core.decipher(encrypted), Ok(letter));
                        assert_eq!(matches!(alphabet.contact(letter).unwrap(), AlphabetContact::Sixes(_)),
                                   matches!(alphabet.contact(decrypted).unwrap(), AlphabetContact::Sixes(_)));
                    }
                    assert_eq!(core.sixes_position(), p(six));
                    assert_eq!(core.twenties_positions(), positions.map(p));
                }
            }
        }
    }

    #[test]
    fn changing_positions_changes_wiring_but_never_steps() {
        let mut core = PurpleCore::new(PurpleAlphabet::default(), p(1), [p(1); 3]);
        let first: Vec<_> = (b'A'..=b'Z').map(|c| core.decipher(c).unwrap()).collect();
        core.set_positions(p(2), [p(2), p(3), p(4)]);
        let second: Vec<_> = (b'A'..=b'Z').map(|c| core.decipher(c).unwrap()).collect();
        assert_ne!(first, second);
        assert_eq!(core.sixes_position(), p(2));
        assert_eq!(core.twenties_positions(), [p(2), p(3), p(4)]);
    }

    #[test]
    fn rejects_non_uppercase_letters_without_state_change() {
        let core = PurpleCore::new(PurpleAlphabet::default(), p(1), [p(1); 3]);
        for byte in [b'a', b' ', 0, 255] {
            assert_eq!(core.decipher(byte), Err(AlphabetError::InvalidInputLetter { byte }));
            assert_eq!(core.encipher(byte), Err(AlphabetError::InvalidInputLetter { byte }));
        }
    }
}
