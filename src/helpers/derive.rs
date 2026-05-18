//! This is a trait to implement ways of generating permutations of a given alphabet, following
//! different rules.
//!
//! The main interest here is for checkerboard variations.  Common point here is that it is always a
//! 10 x N matrix, where N is the number of holes (and thus rows) in the checkerboard.
//!
//! Reference: <https://www.ciphermachinesandcryptology.com/en/table.htm>
//!
//! Algorithms:
//! - Horizontal
//!       You take the base alphabet, extract the most frequet letters according to the `Frequent`
//!       trait, and put them in a new vector.
//!       e.g. given the alphabet "ABCDEFGHIJKLMNOPQRSTUVWXYZ-/", and the `Frequent` trait for English,
//!       the most frequent letters are ATONESIR
//!       The permutation is ATONESIRBCDFGHJKLMPQUVWXYZ-/.
//!       giving us the checkerboard layout:
//!
//!       A T O N E S I R . .
//!       B C D F G H J K L M
//!       P Q U V W X Y Z - /
//!
//! it can also be written as
//!
//!       A T . O N E . S I R
//!       B C D F G H J K L M
//!       P Q U V W X Y Z - /
//!
//!       with a 10x3:
//!
//!       A T O N E S I . . .
//!       B C D F G H J K L M
//!       P Q R U V W X Y Z -
//!       0 1 2 3 4 5 6 7 8 9
//!
//! - Vertical
//!       The idea is the same as Horizontal, but the letters are put in a new vector, vertically.
//!
//!       A T O N E S I R . .
//!       B D G J L P U W Y -
//!       C F H K M Q V X Z /
//!
//! Using a 10x3 checkerboard to include numbers, it would give:
//!
//!       A T O N E S I . . .
//!       B F J M R W Z 2 5 8
//!       C G K P U X 0 3 6 9
//!       D H L Q V Y 1 4 7 -
//!
//!       (it omits the / which was used before to switch between letters and numbers).
//!

use crate::helpers::Frequent;

#[derive(Debug)]
pub struct Horizontal;

#[derive(Debug)]
pub struct Vertical;

pub trait Derive<F: Frequent> {
    fn derive(alphabet: &[u8]) -> Vec<u8>;
}

impl<F: Frequent> Derive<F> for Horizontal {
    fn derive(alphabet: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(alphabet.len());

        for &ch in F::SYMBOLS {
            if alphabet.contains(&ch) && !out.contains(&ch) {
                out.push(ch);
            }
        }

        for &ch in alphabet {
            if !out.contains(&ch) {
                out.push(ch);
            }
        }

        out
    }
}

#[derive(Debug)]
struct English;

impl Frequent for English {
    const SYMBOLS: &'static [u8] = b"ATONESIR--";
}

#[derive(Debug)]
struct EnglishExt;

impl Frequent for EnglishExt {
    const SYMBOLS: &'static [u8] = b"ATONESI---";
}

#[derive(Debug)]
struct EnglishAlt;

impl Frequent for EnglishAlt {
    const SYMBOLS: &'static [u8] = b"ESTONIA---";
}

// -----

impl<F: Frequent> Derive<F> for Vertical {
   fn derive(alphabet: &[u8]) -> Vec<u8> {
        let holes = F::SYMBOLS
            .iter()
            .filter(|&&b| b == b'-')
            .count();

        let top: Vec<u8> = F::SYMBOLS
            .iter()
            .copied()
            .filter(|&b| b != b'-')
            .collect();

        let tail: Vec<u8> = alphabet
            .iter()
            .copied()
            .filter(|b| !top.contains(b))
            .collect();

        let mut out = Vec::with_capacity(top.len() + tail.len());

        // First emit the top-row frequent letters.
        out.extend_from_slice(&top);

        // No straddling rows: vertical == horizontal.
        if holes == 0 {
            out.extend_from_slice(&tail);
            return out;
        }

        // Fill the tail vertically into `holes` rows, then read rows horizontally.
        //
        // For holes = 2:
        //
        // tail: B C D F G H ...
        //
        // fill vertically:
        //
        // row 0: B D G ...
        // row 1: C F H ...
        //
        for row in 0..holes {
            let mut i = row;
            while i < tail.len() {
                out.push(tail[i]);
                i += holes;
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use rstest::*;
    use crate::helpers::derive::{Derive, English, EnglishAlt, EnglishExt, Horizontal, Vertical};

    #[rstest]
    #[case("AT-ONE-SIR", 2)]
    #[case("ES-TO-NI-A", 3)]
    #[case("ESTONIA---", 3)]
    fn test_hole_count(#[case] alphabet: &str, #[case] holes: usize) {
        let res = alphabet.bytes()
            .filter_map(|b| (b == b'-').then_some(1))
            .sum::<usize>();
        assert_eq!(res, holes);
    }

    #[test]
    fn test_horizontal_derive() {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ*/";
        let expected = "ATONESIRBCDFGHJKLMPQUVWXYZ*/".bytes().collect::<Vec<_>>();

        let result = <Horizontal as Derive<English>>::derive(alphabet.as_bytes());
        assert_eq!(String::from_utf8(result).unwrap(), String::from_utf8(expected).unwrap());
    }

    #[test]
    fn test_horizontal_derive_ext() {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ*0123456789";
        let expected = "ATONESIBCDFGHJKLMPQRUVWXYZ*0123456789".bytes().collect::<Vec<_>>();

        let result = <Horizontal as Derive<EnglishExt>>::derive(alphabet.as_bytes());
        assert_eq!(String::from_utf8(result).unwrap(), String::from_utf8(expected).unwrap());
    }

    #[test]
    fn test_vertical_derive() {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ*/";
        let expected = "ATONESIRBDGJLPUWY*CFHKMQVXZ/".bytes().collect::<Vec<_>>();

        let result = <Vertical as Derive<English>>::derive(alphabet.as_bytes());
        assert_eq!(String::from_utf8(result).unwrap(), String::from_utf8(expected).unwrap());
    }

    #[test]
    fn test_vertical_derive_ext() {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789*";
        let expected = "ATONESIBFJMRWZ258CGKPUX0369DHLQVY147*".bytes().collect::<Vec<_>>();

        let result = <Vertical as Derive<EnglishExt>>::derive(alphabet.as_bytes());
        assert_eq!(String::from_utf8(result).unwrap(), String::from_utf8(expected).unwrap());
    }

    #[test]
    fn test_vertical_derive_alt() {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789*";
        let expected = "ESTONIABFJMRWZ258CGKPUX0369DHLQVY147*".bytes().collect::<Vec<_>>();

        let result = <Vertical as Derive<EnglishAlt>>::derive(alphabet.as_bytes());
        assert_eq!(String::from_utf8(result).unwrap(), String::from_utf8(expected).unwrap());
    }
}

