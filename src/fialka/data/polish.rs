//! Polish 3K-series Fialka rotor wiring.
//!
//! Source: Tom Perera and David Hamer, "Technical Description and Wiring Data
//! for Rotors for the M-125-MN and M-125-3MN/-3MP3 Russian Fialka Cipher
//! Machines" (2005), 3K-series internal wiring table:
//! <https://enigmamuseum.com/mfr.htm>
//!
//! The source table numbers contacts from 1 through 30 and gives, for every
//! right/input contact, the corresponding left/output contact for rotors
//! А, Б, В, Г, Д, Е, Ж, З, И, К.  Keeping the transcription in that exact
//! one-based row-oriented form makes it straightforward to compare this file
//! against the published table.  Conversion to our zero-based `Contact`
//! coordinate system occurs only in `wiring()`.

use super::super::{RotorCore, RotorId};

/// Published 3K table, preserving its original one-based values and layout.
///
/// Rows are input contacts А..Й (1..30); columns are rotor identities А..К.
const WIRING_3K_ONE_BASED: [[u8; 10]; 30] = [
    [23, 3, 20, 16, 18, 9, 7, 29, 5, 20],
    [22, 24, 5, 21, 15, 14, 9, 27, 19, 24],
    [3, 20, 7, 28, 1, 13, 5, 15, 2, 8],
    [7, 2, 15, 11, 22, 20, 26, 13, 27, 25],
    [4, 6, 21, 27, 19, 24, 6, 8, 20, 19],
    [8, 21, 27, 3, 16, 8, 4, 2, 26, 1],
    [16, 26, 4, 15, 29, 2, 19, 25, 7, 17],
    [6, 7, 1, 12, 8, 6, 3, 12, 11, 5],
    [10, 18, 22, 24, 17, 5, 8, 6, 16, 15],
    [20, 4, 17, 30, 4, 19, 28, 23, 18, 27],
    [15, 17, 23, 9, 3, 11, 22, 9, 3, 9],
    [17, 23, 13, 17, 14, 28, 12, 18, 13, 12],
    [24, 15, 30, 4, 6, 30, 21, 24, 4, 22],
    [9, 19, 6, 20, 30, 3, 24, 1, 23, 10],
    [30, 10, 26, 25, 23, 18, 23, 14, 28, 18],
    [12, 30, 10, 8, 5, 15, 10, 21, 21, 3],
    [25, 13, 16, 1, 26, 7, 13, 17, 6, 16],
    [11, 28, 14, 29, 13, 25, 1, 10, 24, 30],
    [1, 29, 19, 19, 25, 16, 16, 3, 29, 4],
    [28, 11, 18, 18, 10, 1, 29, 11, 30, 14],
    [27, 9, 29, 14, 12, 12, 2, 22, 15, 7],
    [5, 25, 24, 10, 21, 23, 25, 7, 17, 23],
    [29, 1, 3, 5, 27, 27, 27, 16, 9, 11],
    [26, 14, 12, 23, 20, 29, 15, 4, 12, 2],
    [2, 22, 9, 26, 7, 17, 18, 19, 8, 29],
    [18, 8, 11, 7, 11, 10, 11, 26, 22, 26],
    [21, 27, 2, 6, 24, 21, 14, 5, 25, 28],
    [14, 5, 28, 22, 9, 4, 17, 30, 10, 21],
    [13, 12, 8, 2, 2, 22, 30, 28, 1, 6],
    [19, 16, 25, 13, 28, 26, 20, 20, 14, 13],
];

/// Return one 3K rotor in the documented overall base setting.
///
/// For a PROTON-2 rotor this corresponds to matching body/core, side 1
/// outward, core index at А, and ring at А.  Those mechanical adjustments are
/// modelled in later steps; here the result is the equivalent fixed wiring.
#[must_use]
pub(crate) fn rotor(id: RotorId) -> RotorCore {
    RotorCore::new(id, wiring(id)).expect("published 3K rotor wiring must be a permutation")
}

/// Convert one source-table column to zero-based machine contacts.
fn wiring(id: RotorId) -> [u8; 30] {
    let column = id.index();
    std::array::from_fn(|row| WIRING_3K_ONE_BASED[row][column] - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fialka::{Contact, PositionedRotor, RotorPosition};

    fn contact(one_based: u8) -> Contact {
        Contact::new(one_based - 1).unwrap()
    }

    #[test]
    fn all_ten_published_columns_are_valid_permutations() {
        // Construction validates range and uniqueness via Permutation<30>.
        for id in RotorId::ALL {
            let rotor = rotor(id);
            assert_eq!(rotor.id(), id);
        }
    }

    #[test]
    fn published_reference_connections_match() {
        // Independent spot checks spread across the original Perera/Hamer
        // table.  Source contact numbers are intentionally kept one-based in
        // this test to make comparison with the document direct.
        let a = rotor(RotorId::A);
        assert_eq!(a.right_to_left(contact(1)), contact(23));
        assert_eq!(a.right_to_left(contact(15)), contact(30));
        assert_eq!(a.right_to_left(contact(30)), contact(19));

        let b = rotor(RotorId::B);
        assert_eq!(b.right_to_left(contact(1)), contact(3));
        assert_eq!(b.right_to_left(contact(23)), contact(1));
        assert_eq!(b.right_to_left(contact(30)), contact(16));

        let zh = rotor(RotorId::Zh);
        assert_eq!(zh.right_to_left(contact(4)), contact(26));
        assert_eq!(zh.right_to_left(contact(18)), contact(1));
        assert_eq!(zh.right_to_left(contact(30)), contact(20));

        let k = rotor(RotorId::K);
        assert_eq!(k.right_to_left(contact(1)), contact(20));
        assert_eq!(k.right_to_left(contact(18)), contact(30));
        assert_eq!(k.right_to_left(contact(30)), contact(13));
    }

    #[test]
    fn right_to_left_and_left_to_right_cancel_for_every_3k_rotor() {
        for id in RotorId::ALL {
            let rotor = rotor(id);

            for value in 0..30 {
                let input = Contact::new(value).unwrap();
                let output = rotor.right_to_left(input);
                assert_eq!(rotor.left_to_right(output), input, "rotor {id:?}");

                let output = rotor.left_to_right(input);
                assert_eq!(rotor.right_to_left(output), input, "rotor {id:?}");
            }
        }
    }

    #[test]
    fn positioned_3k_rotors_cancel_at_all_30_positions() {
        for id in RotorId::ALL {
            let core = rotor(id);

            for position in 0..30 {
                let rotor = PositionedRotor::new(
                    core.clone(),
                    RotorPosition::new(position).unwrap(),
                );

                for value in 0..30 {
                    let input = Contact::new(value).unwrap();
                    assert_eq!(
                        rotor.left_to_right(rotor.right_to_left(input)),
                        input,
                        "rotor {id:?}, position {position}, input {value}"
                    );
                    assert_eq!(
                        rotor.right_to_left(rotor.left_to_right(input)),
                        input,
                        "rotor {id:?}, position {position}, input {value}"
                    );
                }
            }
        }
    }

    #[test]
    fn rotor_a_at_b_uses_b_as_the_local_input_contact() {
        // The published 3K table says rotor A maps local input Б (2) to
        // local output Ц (22).  At visible position Б, fixed machine contact А
        // meets local Б; local Ц is displaced back by one position and therefore
        // emerges at fixed machine contact Х (21).
        let rotor = PositionedRotor::new(
            rotor(RotorId::A),
            RotorPosition::new(1).unwrap(),
        );

        assert_eq!(rotor.right_to_left(contact(1)), contact(21));
        assert_eq!(rotor.left_to_right(contact(21)), contact(1));
    }

    #[test]
    fn source_table_columns_each_contain_1_through_30_once() {
        // This test checks the transcription before the zero-based conversion,
        // independently of `Permutation::new`'s zero-based validation.
        for column in 0..10 {
            let mut seen = [false; 30];

            for row in WIRING_3K_ONE_BASED {
                let value = row[column];
                assert!((1..=30).contains(&value));
                assert!(!seen[usize::from(value - 1)], "duplicate {value} in column {column}");
                seen[usize::from(value - 1)] = true;
            }

            assert!(seen.into_iter().all(|present| present));
        }
    }
}
