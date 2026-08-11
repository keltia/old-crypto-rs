//! Building blocks for the Fialka M-125-3 implementation.
//!
//! The cipher core works in a machine-native 30-contact coordinate system.
//! Text alphabets, rotor mechanics, and the complete signal path are layered on
//! top of these primitives in later implementation steps.

mod contact;
mod position;
mod proton2;
mod rotor;
pub(crate) use contact::{CONTACT_COUNT, Contact};
pub(crate) use position::RotorPosition;
pub(crate) use proton2::{CoreSide, Proton2Rotor, RotorBodyId};
pub(crate) use rotor::{PositionedRotor, RotorCore, RotorId};
