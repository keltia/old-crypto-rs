//! Building blocks for the Fialka M-125-3 implementation.
//!
//! The cipher core works in a machine-native 30-contact coordinate system.
//! Text alphabets, rotor mechanics, and the complete signal path are layered on
//! top of these primitives in later implementation steps.

mod commutator;
mod contact;
mod data;
mod drum;
mod entry_disc;
mod machine;
mod mechanics;
mod permutation;
mod position;
mod proton2;
mod reflector;
mod rotor;
mod settings;

pub(crate) use commutator::Commutator;
pub(crate) use contact::{CONTACT_COUNT, Contact};
pub(crate) use drum::{RotationDirection, RotorDrum, RotorSlot, RotorStepSet};
pub(crate) use entry_disc::EntryDisc;
pub(crate) use machine::{FialkaCore, FialkaMachine};
pub(crate) use mechanics::{BlockingPins, RotorBody, RotorBodyId};
pub(crate) use permutation::{Permutation, PermutationError};
pub(crate) use position::RotorPosition;
pub(crate) use proton2::{CoreSide, Proton2Rotor};
pub(crate) use reflector::{CipherDirection, ReflectorResult, ReflectorUnit};
pub(crate) use rotor::{PositionedRotor, RotorCore, RotorId};
pub(crate) use settings::{CoreSetting, RingSetting};
