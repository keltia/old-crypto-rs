//! Implementation of the SIGABA (ECM Mark II) cipher machine.
//!
//! SIGABA was a rotor machine used by the United States during World War II and into the 1950s.
//! It was considered highly secure and was never known to have been broken during its service life.
//!
//! The machine consists of three banks of rotors:
//! * **Cipher Bank**: Five rotors that perform the actual encryption of the message.
//! * **Control Bank**: Five rotors that determine which cipher rotors step.
//! * **Index Bank**: Five small rotors (stationary in this implementation) that further scramble the control bank's output.
//!
//! # References
//! * [Wikipedia: SIGABA](https://en.wikipedia.org/wiki/SIGABA)
//! * [The SIGABA (ECM Mark II) Cipher Machine](http://www.cryptomuseum.com/crypto/usa/sigaba/index.htm)

mod alphabet_rotor;
mod cipher_bank;
mod config;
mod contact;
mod control;
mod control_bank;
mod data;
mod index_rotor;
#[cfg(test)]
mod kat;
mod maze;
mod machine;
mod permutation;
mod public;
mod rotor_set;
mod stepping;
mod text;

pub use alphabet_rotor::Orientation;
pub use config::{
    ConfigError as SigabaConfigError, IndexRotorSetting, LargeRotorBank,
    LargeRotorSetting, SigabaConfig,
};
pub use contact::{Position10 as SigabaIndexPosition, Position26 as SigabaRotorPosition};
pub use data::{IndexRotorId as SigabaIndexRotorId, LargeRotorId as SigabaRotorId, LargeRotorSet};
pub use public::Sigaba;
pub use rotor_set::{RotorKind, RotorSet, RotorSetError};
pub use text::TextError as SigabaTextError;

/// Compatibility interface for block-oriented cipher consumers.
pub trait Block {
    fn block_size(&self) -> usize;
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize;
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize;
}
