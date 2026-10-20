//! Typed wheel and pin-setting foundations for the SG-41 cipher machine.
//!
//! Historical wheel stepping is implemented; the cipher is not yet implemented.

mod error;
mod stepping;
mod types;
mod wheel_bank;

pub use error::WheelError;
pub use stepping::{PreCipherStep, SteppingTrace, step_after_cipher, step_before_cipher, step_crank};
pub use wheel_bank::{PinSnapshot, WheelBank};
pub use types::{
    PinPattern, PinSensor, SIXTH_WHEEL_MARKINGS, WHEEL_COUNT, WHEEL_LENGTHS,
    WheelId, WheelPosition, WindowLabel,
};
