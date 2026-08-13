//! SIGABA CSP-889 text/presentation layer.
//!
//! The electrical machine core operates only on 26 contacts.  Historical
//! operator-facing text handling is layered on top:
//!
//! Encipher input:
//!
//! ```text
//! plaintext A..Y -> same electrical letter
//! plaintext Z    -> electrical X
//! plaintext SPACE-> electrical Z
//! ```
//!
//! This follows the ECM Mark II wiring: with the controller at `E`, the `Z`
//! keylever contact is paralleled with `X`, while the space-bar contact is
//! connected to the `Z` circuit.
//!
//! Decipher output:
//!
//! ```text
//! electrical Z -> SPACE
//! all others   -> corresponding A..Y letter
//! ```
//!
//! Consequently plaintext `Z` is intentionally lossy: after encipher/decipher
//! it appears as `X`.  Ciphertext grouping whitespace is presentation only and
//! is ignored without advancing the machine.
//!
//! Source: CSP 1100(C), *Operating Instructions for ECM Mark 2 and CCM Mark 1*,
//! §§311 and 315, and the controller wiring description in Part 2.

use core::fmt;

use super::{
    contact::Contact26,
    machine::{SigabaCore, SigabaTables},
};

/// Error from the historical SIGABA text adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextError {
    /// The validated configuration could not construct its static reference wiring.
    InvalidConfiguration,
    /// Plaintext contained a character not representable by the wartime
    /// alphabet/space keyboard path used here.
    UnsupportedPlaintext(char),
    /// Ciphertext contained something other than A-Z or grouping whitespace.
    UnsupportedCiphertext(char),
}

impl fmt::Display for TextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::InvalidConfiguration => f.write_str("invalid SIGABA configuration"),
            Self::UnsupportedPlaintext(ch) => write!(
                f,
                "character {ch:?} is not supported by the SIGABA plaintext text layer"
            ),
            Self::UnsupportedCiphertext(ch) => write!(
                f,
                "character {ch:?} is not valid SIGABA ciphertext"
            ),
        }
    }
}

impl std::error::Error for TextError {}

impl From<super::config::ConfigError> for TextError {
    fn from(_: super::config::ConfigError) -> Self {
        Self::InvalidConfiguration
    }
}

/// Encode one human plaintext character into the contact presented to the
/// cipher bank.
///
/// ASCII lowercase is normalized to uppercase.  `Z` deliberately aliases `X`;
/// ordinary ASCII space uses electrical contact Z.
pub(crate) fn plaintext_to_contact(ch: char) -> Result<Contact26, TextError> {
    match ch {
        ' ' => Ok(contact(b'Z')),
        'z' | 'Z' => Ok(contact(b'X')),
        'a'..='y' => Ok(contact(ch.to_ascii_uppercase() as u8)),
        'A'..='Y' => Ok(contact(ch as u8)),
        _ => Err(TextError::UnsupportedPlaintext(ch)),
    }
}

/// Convert one deciphered electrical contact to human plaintext.
///
/// Electrical Z is the printer's word-space path in decipher mode.
#[must_use]
pub(crate) fn contact_to_plaintext(contact: Contact26) -> char {
    if contact.get() == b'Z' - b'A' {
        ' '
    } else {
        char::from(b'A' + contact.get())
    }
}

/// Parse one ciphertext character.
///
/// Returns `Ok(None)` for grouping whitespace, which must not advance the
/// machine state.
pub(crate) fn ciphertext_to_contact(
    ch: char,
) -> Result<Option<Contact26>, TextError> {
    match ch {
        'a'..='z' => Ok(Some(contact(ch.to_ascii_uppercase() as u8))),
        'A'..='Z' => Ok(Some(contact(ch as u8))),
        ' ' | '\t' | '\r' | '\n' => Ok(None),
        _ => Err(TextError::UnsupportedCiphertext(ch)),
    }
}

/// Encipher human plaintext through an already-configured mutable SIGABA core.
///
/// The returned ciphertext is ungrouped uppercase A-Z.  Each plaintext space
/// is a real machine operation and therefore advances the rotor state.
pub(crate) fn encipher_text_with(
    machine: &mut SigabaCore,
    tables: &SigabaTables<'_>,
    src: &str,
) -> Result<String, TextError> {
    let mut output = String::with_capacity(src.len());

    for ch in src.chars() {
        let input = plaintext_to_contact(ch)?;
        let encrypted = machine.encipher_contact_with(tables, input);
        output.push(char::from(b'A' + encrypted.get()));
    }

    Ok(output)
}

/// Decipher human-entered ciphertext through an already-configured mutable
/// SIGABA core.
///
/// ASCII whitespace is treated solely as five-letter-group formatting and is
/// ignored without changing rotor state.
pub(crate) fn decipher_text_with(
    machine: &mut SigabaCore,
    tables: &SigabaTables<'_>,
    src: &str,
) -> Result<String, TextError> {
    let mut output = String::with_capacity(src.len());

    for ch in src.chars() {
        let Some(input) = ciphertext_to_contact(ch)? else {
            continue;
        };

        let decrypted = machine.decipher_contact_with(tables, input);
        output.push(contact_to_plaintext(decrypted));
    }

    Ok(output)
}

#[cfg(test)]
pub(crate) fn encipher_text(
    machine: &mut SigabaCore,
    src: &str,
) -> Result<String, TextError> {
    let tables = machine.resolve_tables(super::data::reference_rotor_set().unwrap());
    encipher_text_with(machine, &tables, src)
}

#[cfg(test)]
pub(crate) fn decipher_text(
    machine: &mut SigabaCore,
    src: &str,
) -> Result<String, TextError> {
    let tables = machine.resolve_tables(super::data::reference_rotor_set().unwrap());
    decipher_text_with(machine, &tables, src)
}

fn contact(letter: u8) -> Contact26 {
    Contact26::new(letter - b'A')
        .expect("ASCII A-Z is always a valid SIGABA alphabet contact")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        alphabet_rotor::{AlphabetRotor, Orientation},
        cipher_bank::CipherBank,
        contact::{Position10, Position26},
        control_bank::ControlBank,
        data::{IndexRotorId, LargeRotorId, LargeRotorSet},
        index_rotor::{IndexBank, IndexRotor},
        maze::SteppingMaze,
    };

    fn large(id: u8) -> AlphabetRotor {
        AlphabetRotor::from_reference(
            LargeRotorSet::PekelneyReference,
            LargeRotorId::new(id).unwrap(),
            Position26::A,
            Orientation::Normal,
        )
        .unwrap()
    }

    fn index(id: u8) -> IndexRotor {
        IndexRotor::from_reference(
            IndexRotorId::new(id).unwrap(),
            Position10::ZERO,
        )
        .unwrap()
    }

    fn machine() -> SigabaCore {
        SigabaCore::new(
            CipherBank::new([
                large(0),
                large(1),
                large(2),
                large(3),
                large(4),
            ]),
            SteppingMaze::new(
                ControlBank::new([
                    large(5),
                    large(6),
                    large(7),
                    large(8),
                    large(9),
                ]),
                IndexBank::new([
                    index(0),
                    index(1),
                    index(2),
                    index(3),
                    index(4),
                ]),
            ),
        )
    }

    #[test]
    fn plaintext_space_uses_electrical_z() {
        assert_eq!(plaintext_to_contact(' ').unwrap(), contact(b'Z'));
    }

    #[test]
    fn plaintext_z_is_paralleled_with_x() {
        assert_eq!(plaintext_to_contact('Z').unwrap(), contact(b'X'));
        assert_eq!(plaintext_to_contact('z').unwrap(), contact(b'X'));
        assert_eq!(
            plaintext_to_contact('Z').unwrap(),
            plaintext_to_contact('X').unwrap(),
        );
    }

    #[test]
    fn deciphered_electrical_z_prints_space() {
        assert_eq!(contact_to_plaintext(contact(b'Z')), ' ');
        assert_eq!(contact_to_plaintext(contact(b'X')), 'X');
        assert_eq!(contact_to_plaintext(contact(b'A')), 'A');
    }

    #[test]
    fn lowercase_plaintext_is_normalized() {
        for (lower, upper) in ('a'..='y').zip('A'..='Y') {
            assert_eq!(
                plaintext_to_contact(lower).unwrap(),
                plaintext_to_contact(upper).unwrap(),
            );
        }
    }

    #[test]
    fn unsupported_plaintext_is_rejected() {
        for ch in ['0', '7', '.', ',', '-', '\n', '\t', 'é'] {
            assert_eq!(
                plaintext_to_contact(ch),
                Err(TextError::UnsupportedPlaintext(ch)),
            );
        }
    }

    #[test]
    fn ciphertext_accepts_letters_and_grouping_whitespace_only() {
        assert_eq!(ciphertext_to_contact('A').unwrap(), Some(contact(b'A')));
        assert_eq!(ciphertext_to_contact('z').unwrap(), Some(contact(b'Z')));

        for ch in [' ', '\t', '\r', '\n'] {
            assert_eq!(ciphertext_to_contact(ch).unwrap(), None);
        }

        for ch in ['0', '.', '-', 'é'] {
            assert_eq!(
                ciphertext_to_contact(ch),
                Err(TextError::UnsupportedCiphertext(ch)),
            );
        }
    }

    #[test]
    fn ordinary_text_round_trips_with_spaces() {
        let plaintext = "THE QUICK BROWN FOX";

        let mut enc = machine();
        let ciphertext = encipher_text(&mut enc, plaintext).unwrap();
        assert!(ciphertext.chars().all(|ch| ch.is_ascii_uppercase()));
        assert_eq!(ciphertext.len(), plaintext.len());

        let mut dec = machine();
        let recovered = decipher_text(&mut dec, &ciphertext).unwrap();

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn plaintext_z_round_trip_is_historically_lossy_to_x() {
        let plaintext = "ZERO ZEBRA RENDEZVOUS";

        let mut enc = machine();
        let ciphertext = encipher_text(&mut enc, plaintext).unwrap();

        let mut dec = machine();
        let recovered = decipher_text(&mut dec, &ciphertext).unwrap();

        assert_eq!(recovered, "XERO XEBRA RENDEXVOUS");
    }

    #[test]
    fn grouped_ciphertext_deciphers_identically_without_extra_steps() {
        let plaintext = "ATTACK AT DAWN";

        let mut enc = machine();
        let ciphertext = encipher_text(&mut enc, plaintext).unwrap();

        let grouped = ciphertext
            .as_bytes()
            .chunks(5)
            .map(|chunk| core::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join(" ");

        let mut ungrouped_machine = machine();
        let ungrouped =
            decipher_text(&mut ungrouped_machine, &ciphertext).unwrap();

        let mut grouped_machine = machine();
        let grouped_plain =
            decipher_text(&mut grouped_machine, &grouped).unwrap();

        assert_eq!(grouped_plain, ungrouped);
        assert_eq!(
            grouped_machine.cipher_positions(),
            ungrouped_machine.cipher_positions(),
        );
        assert_eq!(
            grouped_machine.control_positions(),
            ungrouped_machine.control_positions(),
        );
    }

    #[test]
    fn plaintext_spaces_are_real_machine_operations() {
        let mut with_space = machine();
        let _ = encipher_text(&mut with_space, "A A").unwrap();

        let mut without_space = machine();
        let _ = encipher_text(&mut without_space, "AA").unwrap();

        assert_ne!(
            with_space.control_positions(),
            without_space.control_positions(),
        );
    }

    #[test]
    fn ciphertext_grouping_spaces_are_not_machine_operations() {
        let mut plain = machine();
        let _ = decipher_text(&mut plain, "ABCDE").unwrap();

        let mut grouped = machine();
        let _ = decipher_text(&mut grouped, "AB CDE").unwrap();

        assert_eq!(plain.cipher_positions(), grouped.cipher_positions());
        assert_eq!(plain.control_positions(), grouped.control_positions());
    }
}
