//! Typed wheel and pin-setting foundations for the SG-41 cipher machine.
//!
//! Historical wheel stepping and cage displacement are implemented; the
//! print-head character mapping is implemented; a stateful per-character cipher core is implemented.

mod config;
mod core;
mod displacement;
mod error;
mod print_head;
mod public;
mod stepping;
mod text;
mod types;
mod wheel_bank;

pub use config::Sg41Config;
pub use core::{CharacterCycle, Sg41Core};
pub use displacement::{CAGE_WEIGHTS, Displacement, displacement_from_pins, sense_displacement};
pub use error::{ConfigError, WheelError};
pub use public::SG41;
pub use print_head::{INNER_RING, OUTER_RING, decipher_letter, encipher_letter};
pub use stepping::{PreCipherStep, SteppingTrace, step_after_cipher, step_before_cipher, step_crank};
pub use text::{display_plaintext, format_ciphertext, parse_ciphertext, prepare_plaintext};
pub use wheel_bank::{PinSnapshot, WheelBank};
pub use types::{
    PinPattern, PinSensor, SIXTH_WHEEL_MARKINGS, WHEEL_COUNT, WHEEL_LENGTHS,
    WheelId, WheelPosition, WindowLabel,
};
