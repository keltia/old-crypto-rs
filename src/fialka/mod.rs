//! Building blocks for the Fialka M-125-3 implementation.
//!
//! The cipher core works in a machine-native 30-contact coordinate system.
//! Text alphabets, rotor mechanics, and the complete signal path are layered on
//! top of these primitives in later implementation steps.

mod alphabet;
mod commutator;
mod config;
mod contact;
mod data;
mod drum;
mod entry_disc;
mod keyboard;
mod machine;
mod mechanics;
mod permutation;
mod position;
mod proton2;
mod reflector;
mod rotor;
mod settings;

pub(crate) use alphabet::{
    MixedRegister, RussianAlphabet, RussianSymbol, RussianTextState, TextMode,
};
pub use alphabet::UnsupportedRussianLetter;
pub use commutator::Commutator;
pub use config::{FialkaConfig, FialkaConfigError, RotorConfig, RotorSeries};
pub(crate) use contact::{CONTACT_COUNT, Contact};
pub(crate) use drum::{RotationDirection, RotorDrum, RotorSlot, RotorStepSet};
pub(crate) use entry_disc::EntryDisc;
pub(crate) use keyboard::KeyboardMapping;
pub use machine::Fialka;
pub(crate) use machine::{FialkaCore, FialkaMachine};
pub(crate) use mechanics::{BlockingPins, RotorBody, RotorBodyId};
pub use permutation::PermutationError;
pub(crate) use permutation::Permutation;
pub use position::RotorPosition;
pub use proton2::CoreSide;
pub(crate) use proton2::Proton2Rotor;
pub(crate) use reflector::{CipherDirection, ReflectorResult, ReflectorUnit};
pub use rotor::RotorId;
pub(crate) use rotor::{PositionedRotor, RotorCore};
pub use settings::{CoreSetting, RingSetting};
