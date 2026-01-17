pub mod helpers;
mod null;
mod caesar;
mod playfair;
mod chaocipher;
mod square;
mod transposition;
mod adfgvx;
mod straddling;
mod nihilist;
mod vic;
mod wheatstone;
#[cfg(feature = "sigaba")]
mod sigaba;
mod solitaire;

pub use null::NullCipher;
pub use caesar::CaesarCipher;
pub use playfair::PlayfairCipher;
pub use chaocipher::Chaocipher;
pub use square::SquareCipher;
pub use transposition::Transposition;
pub use transposition::IrregularTransposition;
pub use adfgvx::ADFGVX;
pub use straddling::StraddlingCheckerboard;
pub use nihilist::Nihilist;
pub use vic::VicCipher;
pub use wheatstone::Wheatstone;
#[cfg(feature = "sigaba")]
pub use sigaba::Sigaba;
pub use solitaire::Solitaire;


pub trait Block {
    fn block_size(&self) -> usize;
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize;
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize;
}
