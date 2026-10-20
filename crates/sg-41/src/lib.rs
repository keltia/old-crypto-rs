//! Typed wheel and pin-setting foundations for the SG-41 cipher machine.
//!
//! Historical wheel stepping and cage displacement are implemented; the
//! print-head character mapping is implemented; the full cipher is not yet implemented.

mod displacement;
mod error;
mod print_head;
mod stepping;
mod types;
mod wheel_bank;

pub use displacement::{CAGE_WEIGHTS, Displacement, displacement_from_pins, sense_displacement};
pub use error::WheelError;
pub use print_head::{INNER_RING, OUTER_RING, decipher_letter, encipher_letter};
pub use stepping::{PreCipherStep, SteppingTrace, step_after_cipher, step_before_cipher, step_crank};
pub use wheel_bank::{PinSnapshot, WheelBank};
pub use types::{
    PinPattern, PinSensor, SIXTH_WHEEL_MARKINGS, WHEEL_COUNT, WHEEL_LENGTHS,
    WheelId, WheelPosition, WindowLabel,
};
