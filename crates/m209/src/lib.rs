//! Historical Hagelin M-209 cipher-machine simulation.
//!
//! Step 6 implements the six advancing pin wheels and the 27-bar lug
//! drum; letter conversion and full encryption follow in later steps.
//!
//! The machine will use the shared [`old_crypto_rs::Block`] trait when its
//! public cipher facade is introduced in Step 12. Do not duplicate that trait.

pub mod fixtures;
mod error;
mod drum;
pub use drum::LugDrum;
pub use error::KeyError;
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
