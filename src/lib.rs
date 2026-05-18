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
#[cfg(feature = "sigaba")]
mod sigaba;

pub use null::NullCipher;
pub use vigenere::{Autocrypt, AutocryptCipher, Autokey, AutokeyCipher, Vigenere, VigenereCipher};
pub use caesar::{Caesar, CaesarCipher};
pub use playfair::{Playfair, PlayfairCipher};
pub use chaocipher::{ChaoBasic, Chaocipher};
pub use square::{SquareCipher, PolybiusCipher};
pub use transposition::{Transposition, IrregularTransposition};
pub use adfgvx::{ADFGVXCipher, ADFGXSquare, ADFGVXSquare};
pub use straddling::{EnglishStraddling, FrenchStraddling, GermanStraddling, Straddling};
pub use nihilist::Nihilist;
pub use solitaire::Solitaire;
pub use secom::{SecomCipher, column_order_from_digits};
pub use vic::VicCipher;
pub use wheatstone::{WheatstoneBasic, Wheatstone};
#[cfg(feature = "sigaba")]
pub use sigaba::Sigaba;


pub trait Block {
    fn block_size(&self) -> usize;
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize;
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize;
}
