//! Deterministic internal-indicator derivation for the documented twelve-letter
//! M-209 training procedure. Message framing belongs to Step 21.


use crate::{Contact, IndicatorError, KeyError, KeyList, M209Config, WHEEL_COUNT, WheelId, WheelPosition};

/// The number of system-letter contacts enciphered in this procedure.
pub const INDICATOR_CONTACTS: usize = 12;

/// Fully reproducible intermediate state for the twelve-letter procedure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedIndicator {
    intermediate: String,
    positions: [WheelPosition; WHEEL_COUNT],
}

impl DerivedIndicator {
    /// The twelve letters produced from the repeated system indicator.
    pub fn intermediate(&self) -> &str {
        &self.intermediate
    }

    /// The six selected letters, in physical wheel order.
    pub fn letters(&self) -> String {
        self.positions.iter().map(|position| position.letter()).collect()
    }

    /// Typed wheel positions suitable for constructing a new machine key.
    pub const fn positions(&self) -> &[WheelPosition; WHEEL_COUNT] {
        &self.positions
    }
}

/// Choose the first admissible letter for each wheel in sequence.
///
/// Letters that are not present on the current wheel are discarded rather
/// than re-used for later wheels. This is intentionally not a search for a
/// globally optimal matching of letters to wheels.
fn select_positions(intermediate: &str) -> Result<[WheelPosition; WHEEL_COUNT], IndicatorError> {
    let mut selected = Vec::with_capacity(WHEEL_COUNT);

    for letter in intermediate.chars() {
        if selected.len() == WHEEL_COUNT {
            break;
        }

        let wheel = WheelId::new(selected.len() as u8 + 1)
            .expect("there are exactly six physical M-209 wheels");

        if let Ok(position) = wheel.position_for_letter(letter) {
            selected.push(position);
        }
    }

    let count = selected.len();
    selected.try_into().map_err(|_| IndicatorError::InsufficientLetters { selected: count })
}

/// Derive the secret six-wheel alignment from a named daily key, a system
/// letter, and a six-letter *external* wheel alignment.
///
/// Exactly twelve machine contacts are processed at the external setting.
/// No random choices, body encryption, or message framing are performed.
/// This method does not modify the original `KeyList` or a caller's machine.
pub fn derive_internal_indicator(
    key: &KeyList,
    system: char,
    external: &str,
) -> Result<DerivedIndicator, IndicatorError> {
    if !system.is_ascii_uppercase() {
        return Err(IndicatorError::InvalidSystemLetter(system));
    }

    // Reuse the crate's checked wheel alphabet/length validator through
    // M209Config, rather than duplicating those six alphabet rules here.
    let config = M209Config::new(
        *key.config().pins(),
        external_positions(external)?,
        *key.config().bars(),
    )?;

    let mut machine = config.build_machine();
    let contact = Contact::from_letter(system)
        .expect("validated ASCII uppercase system indicator");

    let intermediate: String = (0..INDICATOR_CONTACTS)
        .map(|_| machine.convert_contact(contact).letter())
        .collect();

    let positions = select_positions(&intermediate)?;

    Ok(DerivedIndicator { intermediate, positions })
}

fn external_positions(external: &str) -> Result<[WheelPosition; WHEEL_COUNT], KeyError> {
    if external.len() != WHEEL_COUNT {
        return Err(KeyError::InvalidIndicatorLength(external.len()));
    }

    let mut positions = Vec::with_capacity(WHEEL_COUNT);

    for (index, letter) in external.chars().enumerate() {
        let wheel = WheelId::new(index as u8 + 1)
            .expect("six wheel indicator positions were checked above");
        positions.push(wheel.position_for_letter(letter)?);
    }

    Ok(positions.try_into().expect("exactly six positions were checked"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{MANUAL_1944_CHECK, MANUAL_1944_PINS, manual_1944_drum};
    use crate::KeyId;

    fn reference_key() -> KeyList {
        let config = M209Config::from_letters(
            MANUAL_1944_PINS,
            "AAAAAA",
            manual_1944_drum(),
        ).unwrap();

        KeyList::new(KeyId::parse("XA").unwrap(), config, MANUAL_1944_CHECK).unwrap()
    }

    #[test]
    fn tutorial_twelve_letter_fixture_and_derived_alignment() {
        let derived = derive_internal_indicator(&reference_key(), 'K', "DUFLJB").unwrap();

        assert_eq!(derived.intermediate(), "PEQGBJGCDFUP");
        assert_eq!(derived.letters(), "PEQGBJ");
        assert_eq!(derived.positions().len(), WHEEL_COUNT);
    }

    #[test]
    fn repeatable_without_mutating_daily_key() {
        let key = reference_key();
        let before = key.clone();

        let first = derive_internal_indicator(&key, 'K', "DUFLJB").unwrap();
        let second = derive_internal_indicator(&key, 'K', "DUFLJB").unwrap();

        assert_eq!(first, second);
        assert_eq!(key, before);
    }

    #[test]
    fn rejects_invalid_system_and_external_indicators() {
        let key = reference_key();

        assert!(matches!(
            derive_internal_indicator(&key, 'k', "DUFLJB"),
            Err(IndicatorError::InvalidSystemLetter('k'))
        ));

        assert!(matches!(
            derive_internal_indicator(&key, 'K', "SHORT"),
            Err(IndicatorError::InvalidExternalIndicator(KeyError::InvalidIndicatorLength(5)))
        ));

        assert!(matches!(
            derive_internal_indicator(&key, 'K', "DUFLJZ"),
            Err(IndicatorError::InvalidExternalIndicator(KeyError::InvalidWheelLetter { .. }))
        ));
    }

    #[test]
    fn selection_skips_letters_not_in_the_current_wheel() {
        // Wheel 2 excludes W, so W must be discarded before accepting A.
        let positions = select_positions("PWAQGBJ").unwrap();
        let letters: String = positions.iter().map(|position| position.letter()).collect();
        assert_eq!(letters, "PAQGBJ");
    }

    #[test]
    fn exhausted_twelve_letter_stream_returns_structured_error() {
        assert_eq!(
            select_positions("WWWWWWWWWWWW"),
            Err(IndicatorError::InsufficientLetters { selected: 1 })
        );
    }
}
