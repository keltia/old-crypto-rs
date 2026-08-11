//! Fixed CSP-889 control-output banding.
//!
//! Four simultaneous signals emerge from the five-wheel control bank.  Their
//! letters are OR-banded into at most four active index-bank inputs:
//!
//! ```text
//! B                -> 1
//! C                -> 2
//! D, E             -> 3
//! F, G, H          -> 4
//! I, J, K          -> 5
//! L, M, N, O       -> 6
//! P, Q, R, S, T    -> 7
//! U, V, W, X, Y, Z -> 8
//! A                -> 9
//! ```
//!
//! Index input 0 is never energized in CSP-889.

use super::contact::{Contact10, Contact26};

/// Active inputs or outputs of the 10-contact index subsystem.
///
/// Only the low ten bits are used.  A bitset models the machine's electrical
/// OR behavior directly: duplicate paths collapse to one active line.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct IndexSignals(u16);

impl IndexSignals {
    const MASK: u16 = 0x03ff;

    #[must_use]
    pub(crate) const fn empty() -> Self {
        Self(0)
    }

    #[must_use]
    pub(crate) const fn from_bits(bits: u16) -> Self {
        Self(bits & Self::MASK)
    }

    #[must_use]
    pub(crate) const fn bits(self) -> u16 {
        self.0
    }

    #[must_use]
    pub(crate) const fn contains(self, contact: Contact10) -> bool {
        self.0 & (1_u16 << contact.get()) != 0
    }

    pub(crate) fn insert(&mut self, contact: Contact10) {
        self.0 |= 1_u16 << contact.get();
    }

    #[must_use]
    pub(crate) const fn count(self) -> u32 {
        self.0.count_ones()
    }
}

/// Map one control-bank output letter to its fixed CSP-889 index input.
#[must_use]
pub(crate) fn control_output_to_index_input(output: Contact26) -> Contact10 {
    let input = match output.get() {
        0 => 9,       // A
        1 => 1,       // B
        2 => 2,       // C
        3..=4 => 3,   // D E
        5..=7 => 4,   // F G H
        8..=10 => 5,  // I J K
        11..=14 => 6, // L M N O
        15..=19 => 7, // P Q R S T
        20..=25 => 8, // U V W X Y Z
        _ => unreachable!("Contact26 is always in 0..26"),
    };

    Contact10::new(input).expect("CSP-889 banding always produces index input 1..9")
}

/// OR-band the four simultaneous control-bank outputs into index inputs.
#[must_use]
pub(crate) fn band_control_outputs(outputs: [Contact26; 4]) -> IndexSignals {
    let mut signals = IndexSignals::empty();

    for output in outputs {
        signals.insert(control_output_to_index_input(output));
    }

    signals
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c26(letter: u8) -> Contact26 {
        Contact26::new(letter - b'A').unwrap()
    }

    fn c10(value: u8) -> Contact10 {
        Contact10::new(value).unwrap()
    }

    #[test]
    fn published_csp889_banding_is_exact() {
        let cases: &[(u8, u8)] = &[
            (b'A', 9),
            (b'B', 1),
            (b'C', 2),
            (b'D', 3), (b'E', 3),
            (b'F', 4), (b'G', 4), (b'H', 4),
            (b'I', 5), (b'J', 5), (b'K', 5),
            (b'L', 6), (b'M', 6), (b'N', 6), (b'O', 6),
            (b'P', 7), (b'Q', 7), (b'R', 7), (b'S', 7), (b'T', 7),
            (b'U', 8), (b'V', 8), (b'W', 8), (b'X', 8), (b'Y', 8), (b'Z', 8),
        ];

        for &(letter, expected) in cases {
            assert_eq!(
                control_output_to_index_input(c26(letter)),
                c10(expected),
                "control output {}",
                char::from(letter)
            );
        }
    }

    #[test]
    fn index_input_zero_is_never_generated() {
        for letter in b'A'..=b'Z' {
            assert_ne!(control_output_to_index_input(c26(letter)), c10(0));
        }
    }

    #[test]
    fn duplicate_control_bands_collapse_electrically() {
        let signals = band_control_outputs([
            c26(b'F'),
            c26(b'G'),
            c26(b'H'),
            c26(b'F'),
        ]);

        assert_eq!(signals.count(), 1);
        assert!(signals.contains(c10(4)));
        assert_eq!(signals.bits(), 1_u16 << 4);
    }

    #[test]
    fn four_distinct_bands_remain_four_active_inputs() {
        let signals = band_control_outputs([
            c26(b'B'),
            c26(b'D'),
            c26(b'L'),
            c26(b'U'),
        ]);

        assert_eq!(signals.count(), 4);
        for input in [1, 3, 6, 8] {
            assert!(signals.contains(c10(input)));
        }
    }

    #[test]
    fn index_signal_mask_discards_nonexistent_contacts() {
        assert_eq!(IndexSignals::from_bits(u16::MAX).bits(), 0x03ff);
    }
}
