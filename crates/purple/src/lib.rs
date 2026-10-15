//! Simulation of the Japanese PURPLE (Angooki Taipu B) cipher machine.
//!
//! Step 2 establishes typed contacts and switch positions. Historical wirings,
//! stepping, configuration and the public cipher API come in later steps.

#![forbid(unsafe_code)]

mod contact;
mod position;

pub use contact::{ContactError, SixesContact, TwentiesContact};
pub use position::{PositionError, SwitchPosition, TwentiesSwitchId};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_smoke_test() {
        assert_eq!(env!("CARGO_PKG_NAME"), "purple");
    }
}
