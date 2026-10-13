//! Implementation of the TSEC/KL-7 (ADONIS / POLLUX) cipher machine.
//!
//! The KL-7 is an off-line rotor cipher machine developed by the Armed Forces Security Agency
//! (AFSA) and the National Security Agency (NSA) in 1952. It served as the primary tactical
//! cipher machine of the United States armed forces and NATO throughout the Cold War.
//!
//! # Architecture
//! - **8-Rotor Drum (KLK-7)**: Eight 36-contact rotors (Rotors 1..8). Rotor 4 is stationary.
//! - **Stepping Unit (KLA-7)**: Seven sensing actuator switches reading 11 exchangeable notch rings.
//! - **Multi-Pass Re-Entry Maze**: 10 loop-back contacts creating multi-pass non-linear signal flow.
//! - **Permutor Board**: Sliding contact assembly switching between Encipher and Decipher signal paths.

#![forbid(unsafe_code)]

pub mod actuator;
pub mod config;
pub mod contact;
pub mod data;
pub mod machine;
pub mod maze;
pub mod notch_ring;
pub mod permutation;
pub mod public;
pub mod rotor;
pub mod stepping;
pub mod text;

pub use actuator::{ActuatorState, ACTUATOR_SWITCH_COUNT, MOVABLE_ROTOR_SLOTS};
pub use config::{ConfigError, KeySheetDto, Kl7Config, OperationMode};
pub use contact::{Contact26, Contact36, Position36, ReentryWire};
pub use data::{BasePlateTerminal, RotorId};
pub use machine::Kl7Core;
pub use maze::{trace_maze, MazeDirection, MazeError, MAX_MAZE_PASSES};
pub use notch_ring::{NotchRing, NotchRingId};
pub use permutation::{Permutation, PermutationError};
pub use public::{Block, Kl7, Kl7Error};
pub use rotor::{Rotor, RotorWiring};
pub use stepping::{evaluate_stepping, RotorStepSet, DRUM_ROTOR_COUNT, STATIONARY_ROTOR_SLOT};
pub use text::{
    contact_to_plaintext, decipher_text_with, encipher_text_with, format_five_letter_groups,
    plaintext_to_contact, TextError,
};
