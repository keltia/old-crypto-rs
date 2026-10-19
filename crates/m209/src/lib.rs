//! Historical Hagelin M-209 cipher-machine simulation.
//!
//! This is the Step 2 workspace skeleton only. It intentionally does not
//! implement wheel, pin, lug, drum, or cipher behavior yet.
//!
//! The machine will use the shared [`old_crypto_rs::Block`] trait when its
//! public cipher facade is introduced in Step 12. Do not duplicate that trait.

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
