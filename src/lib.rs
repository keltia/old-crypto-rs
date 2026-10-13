pub mod helpers;
mod null;
mod vigenere;
mod caesar;
mod error;
mod playfair;
mod chaocipher;
mod square;
mod transposition;
mod adfgvx;
mod straddling;
mod nihilist;
mod secom;
mod solitaire;
mod vic;
mod wheatstone;

pub use null::NullCipher;
pub use vigenere::{Autocrypt, AutocryptCipher, Autokey, AutokeyCipher, Vigenere, VigenereCipher};
pub use caesar::{Caesar, CaesarCipher};
pub use playfair::{Playfair, PlayfairCipher};
pub use chaocipher::{ChaoBasic, Chaocipher};
pub use square::{SquareCipher, PolybiusCipher};
pub use transposition::{Transposition, IrregularTransposition, Disrupted};
pub use adfgvx::{ADFGVXCipher, ADFGXSquare, ADFGVXSquare};
pub use straddling::{EnglishStraddling, FrenchStraddling, GermanStraddling, Straddling};
pub use nihilist::{EnglishNihilist, Nihilist};
pub use solitaire::Solitaire;
pub use secom::{EnglishSecom, FrenchSecom, SecomCipher, column_order_from_digits};
pub use vic::{EnglishVic, VicCipher};
pub use wheatstone::{WheatstoneBasic, Wheatstone};

#[cfg(feature = "fialka")]
pub use fialka::{
    Commutator as FialkaCommutator, CoreSetting as FialkaCoreSetting, CoreSide as FialkaCoreSide,
    Fialka, FialkaConfig, FialkaConfigError, PermutationError as FialkaPermutationError,
    NumericModeError as FialkaNumericError,
    UnsupportedLatinSymbol as FialkaLatinTextError,
    UnsupportedRussianLetter as FialkaTextError,
    RingSetting as FialkaRingSetting, RotorConfig as FialkaRotorConfig, RotorId as FialkaRotorId,
    RotorPosition as FialkaRotorPosition, RotorSeries as FialkaRotorSeries,
};
#[cfg(feature = "sigaba")]
pub use sigaba::{
    LargeRotorBank as SigabaLargeRotorBank, LargeRotorSet as SigabaRotorSet, Orientation as SigabaOrientation, Sigaba,
    SigabaConfig, SigabaConfigError, SigabaIndexPosition, SigabaIndexRotorId,
    SigabaRotorId, SigabaRotorPosition, SigabaTextError, IndexRotorSetting as SigabaIndexRotorSetting,
    LargeRotorSetting as SigabaLargeRotorSetting,
};
#[cfg(feature = "kl-7")]
pub use kl_7::{
    ActuatorState as Kl7ActuatorState, BasePlateTerminal as Kl7BasePlateTerminal,
    ConfigError as Kl7ConfigError, KeySheetDto as Kl7KeySheetDto, Kl7, Kl7Config,
    Kl7Core, Kl7Error, MazeDirection as Kl7MazeDirection, MazeError as Kl7MazeError,
    NotchRing as Kl7NotchRing, NotchRingId as Kl7NotchRingId, OperationMode as Kl7OperationMode,
    Permutation as Kl7Permutation, PermutationError as Kl7PermutationError,
    Position36 as Kl7Position36, ReentryWire as Kl7ReentryWire, Rotor as Kl7Rotor,
    RotorId as Kl7RotorId, RotorStepSet as Kl7RotorStepSet, RotorWiring as Kl7RotorWiring,
    TextError as Kl7TextError, ACTUATOR_SWITCH_COUNT as KL7_ACTUATOR_SWITCH_COUNT,
    DRUM_ROTOR_COUNT as KL7_DRUM_ROTOR_COUNT, MAX_MAZE_PASSES as KL7_MAX_MAZE_PASSES,
    MOVABLE_ROTOR_SLOTS as KL7_MOVABLE_ROTOR_SLOTS,
    STATIONARY_ROTOR_SLOT as KL7_STATIONARY_ROTOR_SLOT,
    contact_to_plaintext as kl7_contact_to_plaintext,
    decipher_text_with as kl7_decipher_text_with,
    encipher_text_with as kl7_encipher_text_with,
    evaluate_stepping as kl7_evaluate_stepping,
    format_five_letter_groups as kl7_format_five_letter_groups,
    plaintext_to_contact as kl7_plaintext_to_contact,
    trace_maze as kl7_trace_maze,
};


pub trait Block {
    fn block_size(&self) -> usize;
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize;
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize;
}

#[cfg(feature = "fialka")]
impl Block for Fialka {
    fn block_size(&self) -> usize {
        fialka::Block::block_size(self)
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        fialka::Block::encrypt(self, dst, src)
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        fialka::Block::decrypt(self, dst, src)
    }
}

#[cfg(feature = "sigaba")]
impl Block for Sigaba {
    fn block_size(&self) -> usize {
        sigaba::Block::block_size(self)
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        sigaba::Block::encrypt(self, dst, src)
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        sigaba::Block::decrypt(self, dst, src)
    }
}

#[cfg(feature = "kl-7")]
impl Block for Kl7 {
    fn block_size(&self) -> usize {
        kl_7::Block::block_size(self)
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        kl_7::Block::encrypt(self, dst, src)
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        kl_7::Block::decrypt(self, dst, src)
    }
}
