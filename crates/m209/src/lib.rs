//! Historical Hagelin M-209 cipher-machine simulation.
//!
//! Step 5 implements six independent pin wheels and historical sensing
//! offsets; the lug drum and encryption will follow in later steps.
//!
//! The machine will use the shared [`old_crypto_rs::Block`] trait when its
//! public cipher facade is introduced in Step 12. Do not duplicate that trait.

pub mod fixtures;
mod types;
mod wheel;
pub use wheel::{PinWheel, WheelBank};
pub use types::{Contact, DRUM_BAR_COUNT, DrumBar, KeyError, Lug, PinPattern,
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
