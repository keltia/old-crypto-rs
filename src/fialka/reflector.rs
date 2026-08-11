//! Reflector and three-point ("Magic") circuit of the Fialka M-125/M-125-3.
//!
//! Fialka's reflector is deliberately not a conventional 30-contact involution.
//! Twenty-six contacts form 13 ordinary reciprocal pairs. Historical contact 13
//! drives the plaintext-enable line, while contacts 16, 18 and 24 are routed
//! through the directed three-point circuit. The MODE selector reverses that
//! three-cycle between coding and decoding.
//!
//! Contact numbers in the historical documentation are one-based. The public
//! machine coordinate used here is [`Contact`], which is zero-based.

use super::Contact;

/// Direction selected by the Fialka MODE switch for cryptographic operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CipherDirection {
    Encode,
    Decode,
}

/// Result of traversing the reflector assembly.
///
/// Most contacts return a signal through the rotor drum. Historical reflector
/// contact 13 instead activates the plaintext-enable line, so no return signal
/// traverses the drum and the original keyboard symbol is emitted directly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReflectorResult {
    ReturnThroughDrum(Contact),
    Plaintext(Contact),
}

/// Fixed reflector and three-point circuit shared by Fialka machines.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ReflectorUnit;

impl ReflectorUnit {
    /// Construct the fixed Fialka reflector assembly.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self
    }

    /// Traverse the reflector assembly in coding or decoding mode.
    ///
    /// `original_input` is the keyboard-side machine contact before any
    /// permutation. It is required only when reflector contact 13 activates
    /// the plaintext-enable circuit.
    #[must_use]
    pub(crate) fn transform(
        self,
        input: Contact,
        direction: CipherDirection,
        original_input: Contact,
    ) -> ReflectorResult {
        match input.get() + 1 {
            // Historical reflector contact 13 is removed from the reciprocal
            // wiring and drives the plaintext-enable line instead.
            13 => ReflectorResult::Plaintext(original_input),

            // Three-point circuit. In coding mode the documented cycle is
            // 16 -> 18 -> 24 -> 16. Decoding selects the inverse cycle.
            16 => ReflectorResult::ReturnThroughDrum(contact(match direction {
                CipherDirection::Encode => 18,
                CipherDirection::Decode => 24,
            })),
            18 => ReflectorResult::ReturnThroughDrum(contact(match direction {
                CipherDirection::Encode => 24,
                CipherDirection::Decode => 16,
            })),
            24 => ReflectorResult::ReturnThroughDrum(contact(match direction {
                CipherDirection::Encode => 16,
                CipherDirection::Decode => 18,
            })),

            // The remaining 26 contacts form 13 ordinary reciprocal pairs.
            1 => ReflectorResult::ReturnThroughDrum(contact(23)),
            23 => ReflectorResult::ReturnThroughDrum(contact(1)),
            2 => ReflectorResult::ReturnThroughDrum(contact(6)),
            6 => ReflectorResult::ReturnThroughDrum(contact(2)),
            3 => ReflectorResult::ReturnThroughDrum(contact(20)),
            20 => ReflectorResult::ReturnThroughDrum(contact(3)),
            4 => ReflectorResult::ReturnThroughDrum(contact(28)),
            28 => ReflectorResult::ReturnThroughDrum(contact(4)),
            5 => ReflectorResult::ReturnThroughDrum(contact(14)),
            14 => ReflectorResult::ReturnThroughDrum(contact(5)),
            7 => ReflectorResult::ReturnThroughDrum(contact(12)),
            12 => ReflectorResult::ReturnThroughDrum(contact(7)),
            8 => ReflectorResult::ReturnThroughDrum(contact(17)),
            17 => ReflectorResult::ReturnThroughDrum(contact(8)),
            9 => ReflectorResult::ReturnThroughDrum(contact(22)),
            22 => ReflectorResult::ReturnThroughDrum(contact(9)),
            10 => ReflectorResult::ReturnThroughDrum(contact(11)),
            11 => ReflectorResult::ReturnThroughDrum(contact(10)),
            15 => ReflectorResult::ReturnThroughDrum(contact(29)),
            29 => ReflectorResult::ReturnThroughDrum(contact(15)),
            19 => ReflectorResult::ReturnThroughDrum(contact(27)),
            27 => ReflectorResult::ReturnThroughDrum(contact(19)),
            21 => ReflectorResult::ReturnThroughDrum(contact(25)),
            25 => ReflectorResult::ReturnThroughDrum(contact(21)),
            26 => ReflectorResult::ReturnThroughDrum(contact(30)),
            30 => ReflectorResult::ReturnThroughDrum(contact(26)),

            _ => unreachable!("Contact guarantees the historical range 1..=30"),
        }
    }
}

/// Convert a historical one-based reflector contact to the internal coordinate.
fn contact(one_based: u8) -> Contact {
    debug_assert!((1..=30).contains(&one_based));
    Contact::new(one_based - 1).expect("reflector constants are valid contacts")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fialka::CONTACT_COUNT;

    fn c(one_based: u8) -> Contact {
        contact(one_based)
    }

    fn returned(result: ReflectorResult) -> Contact {
        match result {
            ReflectorResult::ReturnThroughDrum(contact) => contact,
            ReflectorResult::Plaintext(_) => panic!("expected a return through the drum"),
        }
    }

    #[test]
    fn ordinary_reflector_pairs_match_the_documented_wiring() {
        const PAIRS: [(u8, u8); 13] = [
            (1, 23),
            (2, 6),
            (3, 20),
            (4, 28),
            (5, 14),
            (7, 12),
            (8, 17),
            (9, 22),
            (10, 11),
            (15, 29),
            (19, 27),
            (21, 25),
            (26, 30),
        ];

        let reflector = ReflectorUnit::new();

        for (left, right) in PAIRS {
            for direction in [CipherDirection::Encode, CipherDirection::Decode] {
                assert_eq!(
                    reflector.transform(c(left), direction, Contact::ZERO),
                    ReflectorResult::ReturnThroughDrum(c(right))
                );
                assert_eq!(
                    reflector.transform(c(right), direction, Contact::ZERO),
                    ReflectorResult::ReturnThroughDrum(c(left))
                );
            }
        }
    }

    #[test]
    fn plaintext_enable_returns_the_original_keyboard_contact() {
        let reflector = ReflectorUnit::new();
        let original = c(27);

        for direction in [CipherDirection::Encode, CipherDirection::Decode] {
            assert_eq!(
                reflector.transform(c(13), direction, original),
                ReflectorResult::Plaintext(original)
            );
        }
    }

    #[test]
    fn coding_mode_uses_the_documented_three_point_cycle() {
        let reflector = ReflectorUnit::new();

        assert_eq!(returned(reflector.transform(c(16), CipherDirection::Encode, c(1))), c(18));
        assert_eq!(returned(reflector.transform(c(18), CipherDirection::Encode, c(1))), c(24));
        assert_eq!(returned(reflector.transform(c(24), CipherDirection::Encode, c(1))), c(16));
    }

    #[test]
    fn decoding_mode_reverses_the_three_point_cycle() {
        let reflector = ReflectorUnit::new();

        assert_eq!(returned(reflector.transform(c(16), CipherDirection::Decode, c(1))), c(24));
        assert_eq!(returned(reflector.transform(c(24), CipherDirection::Decode, c(1))), c(18));
        assert_eq!(returned(reflector.transform(c(18), CipherDirection::Decode, c(1))), c(16));
    }

    #[test]
    fn encode_and_decode_are_inverse_on_all_returning_contacts() {
        let reflector = ReflectorUnit::new();

        for value in 0..CONTACT_COUNT as u8 {
            let input = Contact::new(value).unwrap();
            if input == c(13) {
                continue;
            }

            let encoded = returned(reflector.transform(input, CipherDirection::Encode, c(1)));
            let decoded = returned(reflector.transform(encoded, CipherDirection::Decode, c(1)));
            assert_eq!(decoded, input);
        }
    }

    #[test]
    fn direction_only_changes_the_three_magic_contacts() {
        let reflector = ReflectorUnit::new();

        for value in 0..CONTACT_COUNT as u8 {
            let input = Contact::new(value).unwrap();
            let encode = reflector.transform(input, CipherDirection::Encode, c(4));
            let decode = reflector.transform(input, CipherDirection::Decode, c(4));

            if matches!(input.get() + 1, 16 | 18 | 24) {
                assert_ne!(encode, decode);
            } else {
                assert_eq!(encode, decode);
            }
        }
    }
}
