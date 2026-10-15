//! Stateful PURPLE machine, combining electrical substitution and stepping.
//!
//! The initial positions are used to process the first letter. Successful
//! processing then advances the sixes switch and one twenties switch.

use crate::{AlphabetError, PurpleAlphabet, PurpleCore, PurpleMotion, PurpleStepping, SwitchPosition};

/// A PURPLE machine with mutable switch positions.
///
/// Unlike [`PurpleCore`], repeated calls produce a continuous message stream.
/// To start an independent message, construct a new machine or call [`Self::reset`].
pub struct PurpleMachine {
    core: PurpleCore,
    stepping: PurpleStepping,
    initial: PurpleStepping,
}

impl PurpleMachine {
    /// Construct a machine. Twenties positions are in physical order (#1, #2, #3).
    pub fn new(
        alphabet: PurpleAlphabet,
        sixes: SwitchPosition,
        twenties: [SwitchPosition; 3],
        motion: PurpleMotion,
    ) -> Self {
        let stepping = PurpleStepping::new(sixes, twenties, motion);
        Self {
            core: PurpleCore::new(alphabet, sixes, twenties),
            stepping,
            initial: stepping,
        }
    }

    /// Current stepping state, including speed assignment.
    pub const fn state(&self) -> PurpleStepping { self.stepping }

    /// Original stepping state used by [`Self::reset`].
    pub const fn initial_state(&self) -> PurpleStepping { self.initial }

    /// Restore the original positions, without replacing the daily alphabet.
    pub fn reset(&mut self) {
        self.stepping = self.initial;
        self.sync_positions();
    }

    /// Decipher one uppercase ASCII letter, then advance the machine.
    /// Invalid input returns an error and does not advance the switches.
    pub fn decipher(&mut self, letter: u8) -> Result<u8, AlphabetError> {
        let output = self.core.decipher(letter)?;
        self.advance();
        Ok(output)
    }

    /// Encipher one uppercase ASCII letter, then advance the machine.
    /// Invalid input returns an error and does not advance the switches.
    pub fn encipher(&mut self, letter: u8) -> Result<u8, AlphabetError> {
        let output = self.core.encipher(letter)?;
        self.advance();
        Ok(output)
    }

    /// Process a message as uppercase ASCII bytes, without normalization.
    /// A failure leaves the machine at the position before the invalid byte;
    /// previously processed bytes have already advanced its state.
    pub fn decipher_bytes(&mut self, input: &[u8]) -> Result<Vec<u8>, AlphabetError> {
        let mut output = Vec::with_capacity(input.len());
        for &letter in input { output.push(self.decipher(letter)?); }
        Ok(output)
    }

    /// Encipher a message as uppercase ASCII bytes, without normalization.
    pub fn encipher_bytes(&mut self, input: &[u8]) -> Result<Vec<u8>, AlphabetError> {
        let mut output = Vec::with_capacity(input.len());
        for &letter in input { output.push(self.encipher(letter)?); }
        Ok(output)
    }

    fn advance(&mut self) {
        self.stepping.step();
        self.sync_positions();
    }

    fn sync_positions(&mut self) {
        self.core.set_positions(self.stepping.sixes(), self.stepping.twenties());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TwentiesSwitchId::{One, Three, Two};

    fn p(number: u8) -> SwitchPosition { SwitchPosition::new(number).unwrap() }

    fn historical() -> PurpleMachine {
        PurpleMachine::new(
            PurpleAlphabet::new("NOKTYUXEQLHBRMPDICJASVWGZF").unwrap(),
            p(9), [p(1), p(24), p(6)], PurpleMotion::new(Two, Three, One).unwrap(),
        )
    }

    #[test]
    fn first_historical_character_and_post_character_positions() {
        let mut machine = historical();
        assert_eq!(machine.decipher(b'Z'), Ok(b'F'));
        assert_eq!(machine.state().sixes().number(), 10);
        assert_eq!(machine.state().twenties().map(SwitchPosition::number), [1, 25, 6]);
    }

    #[test]
    fn round_trip_across_many_turnovers() {
        let plaintext: Vec<u8> = (0..2000).map(|i| b'A' + (i % 26) as u8).collect();
        let ciphertext = historical().encipher_bytes(&plaintext).unwrap();
        let recovered = historical().decipher_bytes(&ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
        assert_ne!(ciphertext, plaintext);
    }

    #[test]
    fn split_calls_equal_continuous_processing_and_reset_replays() {
        let input = b"THEPURPLEMACHINEISNOWONLINE";
        let mut whole = historical();
        let expected = whole.encipher_bytes(input).unwrap();
        let final_state = whole.state();

        let mut split = historical();
        let mut actual = split.encipher_bytes(&input[..11]).unwrap();
        actual.extend(split.encipher_bytes(&input[11..]).unwrap());
        assert_eq!(actual, expected);
        assert_eq!(split.state(), final_state);

        split.reset();
        assert_eq!(split.state(), split.initial_state());
        assert_eq!(split.encipher_bytes(input).unwrap(), expected);
    }

    #[test]
    fn invalid_input_does_not_advance() {
        let mut machine = historical();
        let original = machine.state();
        assert_eq!(machine.encipher(b' '), Err(AlphabetError::InvalidInputLetter { byte: b' ' }));
        assert_eq!(machine.state(), original);
        assert_eq!(machine.decipher(b'a'), Err(AlphabetError::InvalidInputLetter { byte: b'a' }));
        assert_eq!(machine.state(), original);
        assert_eq!(machine.encipher_bytes(b"AB!CD"), Err(AlphabetError::InvalidInputLetter { byte: b'!' }));
        let mut expected = historical();
        expected.encipher_bytes(b"AB").unwrap();
        assert_eq!(machine.state(), expected.state());
    }

    #[test]
    fn explicit_turnover_matches_separate_stepping_engine() {
        let motion = PurpleMotion::new(One, Two, Three).unwrap();
        let alphabet = PurpleAlphabet::default();
        let mut machine = PurpleMachine::new(alphabet, p(23), [p(1), p(25), p(5)], motion);
        let mut stepping = machine.state();
        for _ in 0..100 {
            machine.decipher(b'A').unwrap();
            stepping.step();
            assert_eq!(machine.state(), stepping);
        }
    }
}
