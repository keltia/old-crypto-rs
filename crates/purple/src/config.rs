//! Validated, immutable PURPLE key settings.
//!
//! The constituent types enforce alphabet, position and speed assignment
//! validity at construction time. No extra unchecked integer settings are kept.

use crate::{PurpleAlphabet, PurpleMachine, PurpleMotion, SwitchPosition};

/// Key and starting state for one PURPLE message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PurpleConfig {
    alphabet: PurpleAlphabet,
    sixes: SwitchPosition,
    twenties: [SwitchPosition; 3],
    motion: PurpleMotion,
}

impl PurpleConfig {
    /// Construct from validated settings. Twenties positions are #1, #2, #3.
    pub const fn new(alphabet: PurpleAlphabet, sixes: SwitchPosition,
        twenties: [SwitchPosition; 3], motion: PurpleMotion) -> Self {
        Self { alphabet, sixes, twenties, motion }
    }

    pub const fn alphabet(&self) -> &PurpleAlphabet { &self.alphabet }
    pub const fn sixes(&self) -> SwitchPosition { self.sixes }
    pub const fn twenties(&self) -> [SwitchPosition; 3] { self.twenties }
    pub const fn motion(&self) -> PurpleMotion { self.motion }

    /// Create an independent, initially positioned stateful machine.
    pub fn build_machine(&self) -> PurpleMachine {
        PurpleMachine::new(self.alphabet.clone(), self.sixes, self.twenties, self.motion)
    }
}
