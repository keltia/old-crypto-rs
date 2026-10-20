//! Historical SG-41 print-head ring conversion (Table 2).
//!
//! The two outer rings (1, 4) have the same markings, as do the two inner
//! rings (2, 3). The print head moves forward by the cage displacement in
//! both encipherment and decipherment; selecting the other pair of rings
//! makes the two operations reciprocal.

/// Ring 1 (ciphertext) and ring 4 (plaintext), positions 1–26 in the
/// physical print-head advancement direction, as transcribed from Table 2.
pub const OUTER_RING: &str = "PAKRHFIDZQNXMTBWJVGSOCLYUE";

/// Ring 2 (ciphertext) and ring 3 (plaintext), same physical position order.
pub const INNER_RING: &str = "FHRKAPEUYLCOSGVJWBTMXNQZDI";

const RING_SIZE: usize = 26;

/// Encipher one uppercase letter using a displacement from 0 through 25.
///
/// Locate the plaintext letter on ring 4, advance the head by `steps`, and
/// read the resulting ciphertext from ring 2. Invalid letters or a value
/// outside the cage displacement range return `None`.
pub fn encipher_letter(plaintext: char, steps: u8) -> Option<char> {
    transform(plaintext, steps)
}

/// Decipher one uppercase letter using the same displacement.
///
/// Locate the ciphertext letter on ring 1, advance the head by `steps`, and
/// read the resulting plaintext from ring 3. The ring arrangement—not a
/// negative displacement—makes this the reciprocal of `encipher_letter`.
pub fn decipher_letter(ciphertext: char, steps: u8) -> Option<char> {
    transform(ciphertext, steps)
}

// The same mechanical movement operates for both ring selections. Outer-ring
// input and inner-ring output have reciprocal physical letter orders.
fn transform(letter: char, steps: u8) -> Option<char> {
    if !letter.is_ascii_uppercase() || steps > 25 {
        return None;
    }

    let position = OUTER_RING.bytes().position(|c| c == letter as u8)?;
    let output = INNER_RING.as_bytes()[(position + steps as usize) % RING_SIZE];

    Some(char::from(output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rings_are_complete_permutations() {
        for ring in [OUTER_RING, INNER_RING] {
            assert_eq!(ring.len(), RING_SIZE);
            let mut sorted = ring.as_bytes().to_vec();
            sorted.sort_unstable();
            assert_eq!(sorted, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        }
    }

    #[test]
    fn documented_eight_step_examples() {
        // Table 3: V at ring-4 position 18 -> ring-2 position 26 = I.
        assert_eq!(encipher_letter('V', 8), Some('I'));
        // Table 3: I at ring-1 position 7 -> ring-3 position 15 = V.
        assert_eq!(decipher_letter('I', 8), Some('V'));
    }

    #[test]
    fn reciprocal_for_every_letter_and_displacement() {
        for steps in 0..=25 {
            for letter in 'A'..='Z' {
                let encoded = encipher_letter(letter, steps).unwrap();
                assert_eq!(decipher_letter(encoded, steps), Some(letter));
            }
        }
    }

    #[test]
    fn invalid_input_is_rejected() {
        for letter in ['a', ' ', '3', 'Ä'] {
            assert_eq!(encipher_letter(letter, 8), None);
            assert_eq!(decipher_letter(letter, 8), None);
        }
        assert_eq!(encipher_letter('A', 26), None);
        assert_eq!(decipher_letter('A', u8::MAX), None);
    }
}
