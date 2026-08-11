//! Czechoslovak 6K-series Fialka rotor data.
//!
//! Sources:
//! - Paul Reuvers, 6K-series wiring measurements, reproduced in the Fialka
//!   Reference Manual and at <https://enigmamuseum.com/mfr.htm>.
//! - Tom Perera, David Hamer and Paul Reuvers, 6K-series advance-blocking-pin
//!   table: <https://enigmamuseum.com/mfr.htm>.
//!
//! As with the Polish 3K data, source coordinates are kept one-based here so
//! the transcription can be reviewed directly against the historical tables.
//! Conversion to the crate's zero-based `Contact` representation happens only
//! at the construction boundary.

use super::super::{BlockingPins, RotorBody, RotorBodyId, RotorCore, RotorId};

/// Published 6K wiring table in one-based source coordinates.
///
/// Rows are input contacts А..Й (1..30); columns are rotor identities А..К.
const WIRING_6K_ONE_BASED: [[u8; 10]; 30] = [
    [13, 20, 29, 4, 18, 16, 26, 16, 12, 9],
    [22, 8, 11, 12, 2, 4, 23, 22, 1, 21],
    [8, 5, 4, 19, 15, 14, 7, 14, 17, 8],
    [18, 15, 22, 29, 7, 24, 5, 30, 29, 16],
    [20, 4, 24, 24, 20, 23, 13, 24, 6, 25],
    [12, 28, 16, 23, 28, 19, 8, 15, 4, 5],
    [28, 21, 18, 7, 8, 30, 24, 17, 7, 20],
    [4, 1, 2, 30, 13, 3, 30, 20, 11, 22],
    [15, 24, 23, 15, 23, 1, 29, 4, 15, 4],
    [27, 13, 3, 1, 12, 8, 20, 7, 3, 27],
    [3, 29, 17, 20, 19, 27, 22, 27, 21, 14],
    [5, 12, 8, 14, 27, 13, 9, 12, 25, 19],
    [16, 14, 20, 18, 4, 9, 12, 6, 9, 1],
    [14, 23, 5, 2, 24, 5, 10, 13, 26, 15],
    [23, 25, 28, 16, 10, 29, 25, 25, 30, 30],
    [26, 7, 12, 27, 14, 10, 16, 21, 13, 2],
    [1, 9, 15, 10, 11, 15, 3, 1, 22, 10],
    [25, 30, 26, 25, 6, 26, 21, 5, 20, 17],
    [17, 27, 30, 17, 30, 22, 19, 26, 10, 7],
    [11, 3, 7, 28, 3, 7, 18, 8, 24, 24],
    [30, 11, 21, 6, 17, 25, 4, 11, 27, 12],
    [10, 18, 19, 21, 26, 17, 1, 23, 14, 18],
    [24, 17, 13, 11, 22, 20, 28, 29, 28, 29],
    [7, 19, 10, 8, 1, 11, 27, 28, 23, 3],
    [6, 22, 27, 22, 29, 2, 6, 3, 2, 23],
    [21, 10, 25, 5, 25, 6, 2, 18, 5, 6],
    [29, 2, 9, 9, 16, 21, 15, 10, 19, 13],
    [2, 26, 1, 3, 21, 28, 17, 19, 18, 28],
    [9, 6, 14, 26, 5, 18, 11, 2, 16, 26],
    [19, 16, 6, 13, 9, 12, 14, 9, 8, 11],
];

/// Published 6K advance-blocking-pin positions in one-based physical wheel
/// coordinates. The outer array follows wheel identities А, Б, В, Г, Д, Е,
/// Ж, З, И, К.
const BLOCKING_PINS_6K_ONE_BASED: [&[u8]; 10] = [
    &[1, 2, 3, 5, 7, 11, 13, 14, 16, 17, 19, 20, 22, 23, 24, 25, 27, 29, 30],
    &[6, 8, 13, 16, 18, 20, 22, 24, 25, 27, 29],
    &[4, 8, 12, 18, 21, 27, 29],
    &[1, 3, 6, 7, 8, 10, 11, 12, 13, 14, 18, 19, 20, 21, 23, 25, 26, 27, 29],
    &[10, 13, 18, 22, 24, 29, 30],
    &[3, 6, 7, 8, 12, 13, 14, 18, 19, 20, 21, 22, 24, 25, 26, 28, 30],
    &[1, 2, 3, 7, 8, 9, 15, 16, 17, 19, 21, 22, 23, 24, 25, 26, 29],
    &[2, 3, 7, 8, 20, 24, 26, 27, 28, 29, 30],
    &[2, 5, 6, 11, 18, 22, 25],
    &[1, 2, 3, 5, 6, 8, 9, 10, 12, 13, 14, 15, 16, 18, 19, 20, 22, 23, 24, 26, 27, 29, 30],
];

/// Return one 6K rotor core in the documented overall base setting.
#[must_use]
pub(crate) fn rotor(id: RotorId) -> RotorCore {
    RotorCore::new(id, wiring(id)).expect("published 6K rotor wiring must be a permutation")
}

/// Return one Czechoslovak 6K mechanical wheel body in source/base ring
/// coordinates.
#[must_use]
pub(crate) fn body(id: RotorId) -> RotorBody {
    let blocking_pins = BlockingPins::from_one_based(BLOCKING_PINS_6K_ONE_BASED[id.index()])
        .expect("published 6K blocking-pin positions must be valid");

    RotorBody::new(RotorBodyId::new(id), blocking_pins)
}

fn wiring(id: RotorId) -> [u8; 30] {
    let column = id.index();
    std::array::from_fn(|row| WIRING_6K_ONE_BASED[row][column] - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fialka::Contact;

    fn contact(one_based: u8) -> Contact {
        Contact::new(one_based - 1).unwrap()
    }

    #[test]
    fn all_ten_6k_columns_are_valid_permutations() {
        for id in RotorId::ALL {
            let rotor = rotor(id);
            assert_eq!(rotor.id(), id);
        }
    }

    #[test]
    fn published_6k_reference_connections_match() {
        let a = rotor(RotorId::A);
        assert_eq!(a.right_to_left(contact(1)), contact(13));
        assert_eq!(a.right_to_left(contact(17)), contact(1));
        assert_eq!(a.right_to_left(contact(30)), contact(19));

        let b = rotor(RotorId::B);
        assert_eq!(b.right_to_left(contact(1)), contact(20));
        assert_eq!(b.right_to_left(contact(8)), contact(1));
        assert_eq!(b.right_to_left(contact(30)), contact(16));

        let zh = rotor(RotorId::Zh);
        assert_eq!(zh.right_to_left(contact(1)), contact(26));
        assert_eq!(zh.right_to_left(contact(22)), contact(1));
        assert_eq!(zh.right_to_left(contact(30)), contact(14));

        let k = rotor(RotorId::K);
        assert_eq!(k.right_to_left(contact(1)), contact(9));
        assert_eq!(k.right_to_left(contact(13)), contact(1));
        assert_eq!(k.right_to_left(contact(30)), contact(11));
    }

    #[test]
    fn right_to_left_and_left_to_right_cancel_for_every_6k_rotor() {
        for id in RotorId::ALL {
            let rotor = rotor(id);
            for raw in 0..30 {
                let input = Contact::new(raw).unwrap();
                assert_eq!(rotor.left_to_right(rotor.right_to_left(input)), input);
                assert_eq!(rotor.right_to_left(rotor.left_to_right(input)), input);
            }
        }
    }

    #[test]
    fn source_wiring_columns_each_contain_1_through_30_once() {
        for column in 0..10 {
            let mut seen = [false; 30];
            for row in WIRING_6K_ONE_BASED {
                let value = row[column];
                assert!((1..=30).contains(&value));
                assert!(!seen[usize::from(value - 1)], "duplicate {value} in column {column}");
                seen[usize::from(value - 1)] = true;
            }
            assert!(seen.into_iter().all(|present| present));
        }
    }

    #[test]
    fn all_ten_6k_blocking_pin_sets_match_the_source_table() {
        for id in RotorId::ALL {
            let body = body(id);
            assert_eq!(body.id().rotor_id(), id);
            let expected = BLOCKING_PINS_6K_ONE_BASED[id.index()];
            assert_eq!(body.blocking_pins().len() as usize, expected.len());

            for one_based in 1..=30 {
                assert_eq!(
                    body.has_blocking_pin(contact(one_based)),
                    expected.contains(&one_based),
                    "wheel {id:?}, source position {one_based}"
                );
            }
        }
    }

    #[test]
    fn published_6k_pin_count_pattern_is_preserved() {
        let expected = [19, 11, 7, 19, 7, 17, 17, 11, 7, 23];
        for (id, expected_count) in RotorId::ALL.into_iter().zip(expected) {
            assert_eq!(body(id).blocking_pins().len(), expected_count);
        }
    }

    #[test]
    fn six_k_data_is_not_accidentally_the_polish_three_k_data() {
        // Same rotor identity and base coordinates, but a different national
        // series must produce different electrical and mechanical data.
        let a_6k = rotor(RotorId::A);
        let a_3k = crate::fialka::data::polish::rotor(RotorId::A);
        assert_ne!(a_6k.right_to_left(contact(1)), a_3k.right_to_left(contact(1)));

        let body_6k = body(RotorId::A);
        let body_3k = crate::fialka::data::polish::body(RotorId::A);
        assert_ne!(body_6k.blocking_pins(), body_3k.blocking_pins());
    }
}
