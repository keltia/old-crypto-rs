//! Building blocks for the Fialka M-125-3 implementation.
//!
//! The cipher core works in a machine-native 30-contact coordinate system.
//! Text alphabets, rotor mechanics, and the complete signal path are layered on
//! top of these primitives in later implementation steps.

mod contact;
mod data;
mod drum;
mod mechanics;
mod permutation;
mod position;
mod proton2;
mod rotor;
mod settings;

pub(crate) use contact::{CONTACT_COUNT, Contact};
pub(crate) use drum::{RotationDirection, RotorDrum, RotorSlot, RotorStepSet};
pub(crate) use mechanics::{BlockingPins, RotorBody, RotorBodyId};
pub(crate) use permutation::{Permutation, PermutationError};
pub(crate) use position::RotorPosition;
pub(crate) use proton2::{CoreSide, Proton2Rotor};
pub(crate) use rotor::{PositionedRotor, RotorCore, RotorId};
pub(crate) use settings::{CoreSetting, RingSetting};
