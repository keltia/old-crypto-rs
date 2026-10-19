//! Structured errors for Fialka configuration and numeric operation.

use thiserror::Error;

use crate::RotorId;

/// Errors rejected before a keyed Fialka machine is assembled.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FialkaConfigError {
    /// The same mechanical wheel body occurs in more than one physical slot.
    #[error(
        "Fialka wheel body {body:?} is used in both slots {} and {}",
        .first_slot + 1,
        .second_slot + 1
    )]
    DuplicateBody {
        body: RotorId,
        first_slot: usize,
        second_slot: usize,
    },

    /// The same removable electrical core occurs in more than one slot.
    #[error(
        "Fialka wiring core {core:?} is used in both slots {} and {}",
        .first_slot + 1,
        .second_slot + 1
    )]
    DuplicateCore {
        core: RotorId,
        first_slot: usize,
        second_slot: usize,
    },
}

/// Errors arising from the M-125-3 numbers-only reduction circuit.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum NumericModeError {
    #[error("character {0:?} is not a decimal digit accepted by Fialka NumLock")]
    UnsupportedCharacter(char),

    #[error("Fialka NumLock reduction entered a cycle at reflector contact {reflector_contact}")]
    ReductionCycle { reflector_contact: u8 },

    #[error("Fialka NumLock produced non-numeric keyboard contact {contact}")]
    NonNumericOutput { contact: u8 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_preserve_existing_format() {
        assert_eq!(
            FialkaConfigError::DuplicateBody {
                body: RotorId::A,
                first_slot: 0,
                second_slot: 9,
            }
            .to_string(),
            "Fialka wheel body A is used in both slots 1 and 10"
        );

        assert_eq!(
            NumericModeError::UnsupportedCharacter('x').to_string(),
            "character 'x' is not a decimal digit accepted by Fialka NumLock"
        );
    }
}
