//! Historical Hagelin M-209 cipher-machine simulation.
//!
//! Provides the validated mechanical core, historical checks, named key lists,
//! twelve-contact derived message indicators, and complete message envelopes.
//! The public cipher facade uses the shared [`old_crypto_rs::Block`] trait.

pub mod fixtures;
mod error;
mod core;
mod drum;
mod config;
mod machine;
mod key_list;
mod indicator;
mod message;
pub use message::{MessageEnvelope, EncipheredMessage, DecipheredMessage, encipher_message, decipher_message};
pub use indicator::{derive_internal_indicator, DerivedIndicator, INDICATOR_CONTACTS};
pub use key_list::{KeyId, KeyList, KeyStore};
mod public;
pub use core::M209Core;
pub use config::M209Config;
pub use drum::LugDrum;
pub use machine::M209Machine;
pub use public::M209;
pub use error::{IndicatorError, KeyError, KeyListError, MessageError, TextError};
mod text;
pub use text::{decrypt_text, decrypt_text_raw, display_plaintext, encrypt_text, group_five, prepare_plaintext, ungroup_ciphertext};
mod types;
mod wheel;
pub use wheel::{PinWheel, WheelBank};
pub use types::{Contact, DRUM_BAR_COUNT, DrumBar, Lug, PinPattern,
    WHEEL_ALPHABETS, WHEEL_COUNT, WHEEL_SIZES, WheelId, WheelPosition};

/// Name of the historical machine represented by this crate.
pub const MACHINE_NAME: &str = "Hagelin M-209";

#[cfg(test)]
mod tests {
    use super::MACHINE_NAME;

    #[test]
    fn crate_smoke_test() {
        assert_eq!(MACHINE_NAME, "Hagelin M-209");
    }
}
