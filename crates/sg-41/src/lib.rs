//! Typed wheel and pin-setting foundations for the SG-41 cipher machine.
//!
//! The SG-41 cryptographic transformation and stepping are not implemented yet.

mod error;
mod types;
mod wheel_bank;

pub use error::WheelError;
pub use wheel_bank::{PinSnapshot, WheelBank};
pub use types::{
    PinPattern, PinSensor, SIXTH_WHEEL_MARKINGS, WHEEL_COUNT, WHEEL_LENGTHS,
    WheelId, WheelPosition, WindowLabel,
};
