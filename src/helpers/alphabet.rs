//! Trait used to represent different alphabets and their operations.
//!
//! This module provides a trait `Alphabet` that is used to represent different
//! alphabets and their operations. It allows for generic code to work with
//! different alphabets without needing to know the specifics of each alphabet.
//!
//! # Alphabet Types
//!
//! The `Alphabet` trait defines a set of constants and functions that are used
//! to convert between characters and their numeric representation (indices)
//!

use crate::helpers::SC_ALPHABET;

/// Marker type representing a 25-letter Latin alphabet (A-Z with I/J merged).
///
/// This type is used as a type parameter to specify that an operation should work
/// with a 25-letter alphabet where 'I' and 'J' are treated as the same character.
/// This configuration is commonly used in classical ciphers like Playfair that
/// require a 5×5 grid (25 characters).
///
/// # Character Mapping
///
/// The alphabet treats 'I' and 'J' as equivalent, mapping both to index 8:
/// - 'A' through 'H' map to indices 0-7
/// - 'I' and 'J' both map to index 8
/// - 'K' through 'Z' map to indices 9-24
///
/// # Examples
///
/// ```
/// use old_crypto_rs::helpers::{Alphabet, Latin25};
///
/// // Normalize 'A' to index 0
/// assert_eq!(Latin25::normalize(b'A'), Some(0));
/// assert_eq!(Latin25::normalize(b'I'), Some(8));
/// assert_eq!(Latin25::normalize(b'J'), Some(8)); // J maps to same index as I
/// assert_eq!(Latin25::normalize(b'Z'), Some(24));
/// assert_eq!(Latin25::normalize(b'0'), None); // Digits not supported
///
/// // Denormalize index back to character
/// assert_eq!(Latin25::denormalize(0), b'A');
/// assert_eq!(Latin25::denormalize(8), b'I'); // Always returns 'I' for index 8
/// assert_eq!(Latin25::denormalize(24), b'Z');
/// ```
///
/// # Use Cases
///
/// This alphabet is specifically designed for ciphers that require a 5×5 grid:
/// - Playfair cipher
/// - Polybius square
/// - ADFGX cipher
/// - Other classical ciphers requiring 25 characters
///
#[derive(Debug)]
pub struct Latin25;

/// Marker type representing the standard 26-letter Latin alphabet (A-Z).
///
/// This type is used as a type parameter to specify that an operation should work
/// with only uppercase letters A through Z, without digits or special characters.
///
/// # Examples
///
/// ```
/// use old_crypto_rs::helpers::{Alphabet, Latin26};
///
/// // Normalize 'A' to index 0
/// assert_eq!(Latin26::normalize(b'A'), Some(0));
/// assert_eq!(Latin26::normalize(b'Z'), Some(25));
/// assert_eq!(Latin26::normalize(b'0'), None); // Digits not supported
///
/// // Denormalize index back to character
/// assert_eq!(Latin26::denormalize(0), b'A');
/// assert_eq!(Latin26::denormalize(25), b'Z');
/// ```
#[derive(Debug)]
pub struct Latin26;

/// Marker type representing an extended 36-character alphabet (A-Z and 0-9).
///
/// This type is used as a type parameter to specify that an operation should work
/// with uppercase letters A through Z (indices 0-25) and digits 0 through 9 (indices 26-35).
/// This is commonly used in ciphers that need to handle alphanumeric input.
///
/// # Examples
///
/// ```
/// use old_crypto_rs::helpers::{Alphabet, Latin36};
///
/// // Normalize letters
/// assert_eq!(Latin36::normalize(b'A'), Some(0));
/// assert_eq!(Latin36::normalize(b'Z'), Some(25));
///
/// // Normalize digits
/// assert_eq!(Latin36::normalize(b'0'), Some(26));
/// assert_eq!(Latin36::normalize(b'9'), Some(35));
///
/// // Denormalize back to characters
/// assert_eq!(Latin36::denormalize(0), b'A');
/// assert_eq!(Latin36::denormalize(25), b'Z');
/// assert_eq!(Latin36::denormalize(26), b'0');
/// assert_eq!(Latin36::denormalize(35), b'9');
/// ```
///
#[derive(Debug)]
pub struct Latin36;

#[derive(Debug)]
pub struct LatinSC;

/// Marker type representing an extended alphabet for the SECOM cipher (A-Z, 0-9, and 3 more symbols).
///
/// This type is used as a type parameter to specify that an operation should work
/// with uppercase letters A through Z (indices 0-25) and digits 0 through 9 (indices 26-35).
/// This is commonly used in ciphers that need to handle alphanumeric input.
///
/// # Examples
///
/// ```
/// use old_crypto_rs::helpers::{Alphabet, Latin36};
///
/// // Normalize letters
/// assert_eq!(LatinSecom::normalize(b'A'), Some(0));
/// assert_eq!(LatinSecom::normalize(b'Z'), Some(25));
///
/// // Normalize digits
/// assert_eq!(LatinSecom::normalize(b'0'), Some(26));
/// assert_eq!(LatinSecom::normalize(b'9'), Some(35));
///
/// // Denormalize back to characters
/// assert_eq!(LatinSecom::denormalize(0), b'A');
/// assert_eq!(LatinSecom::denormalize(25), b'Z');
/// assert_eq!(LatinSecom::denormalize(26), b'0');
/// assert_eq!(LatinSecom::denormalize(35), b'9');
/// ```
///
#[derive(Debug)]
pub struct LatinSecom;

/// Trait defining operations for working with different alphabet encodings in classical ciphers.
///
/// This trait provides a consistent interface for converting between characters and their
/// numeric representations (0-based indices) for different alphabets. It's designed as a
/// zero-cost abstraction using marker types, allowing compile-time selection of alphabet
/// configurations without runtime overhead.
///
/// The trait is primarily used internally by cipher implementations to handle character
/// encoding/decoding in a generic way that works with both standard 26-letter alphabets
/// and extended alphanumeric alphabets.
///
/// # Design Pattern
///
/// This trait uses the "type-level programming" pattern with marker types (`Latin26`, `Latin36`)
/// to provide zero-cost alphabet selection at compile time. All methods are provided via
/// associated constants and functions, requiring no runtime state.
///
/// # Implementations
///
/// - [`Latin25`] - Standard 25-letter alphabet (A-Z) with I/J merged to fix in a 5x5 square
/// - [`Latin26`] - Standard 26-letter alphabet (A-Z)
/// - [`Latin36`] - Extended 36-character alphabet (A-Z, 0-9)
///
/// # Examples
///
/// Using with generic code:
///
/// ```
/// use old_crypto_rs::helpers::{Alphabet, Latin26, Latin36};
///
/// fn encode_char<A: Alphabet>(ch: u8) -> Option<usize> {
///     A::normalize(ch)
/// }
///
/// // Works with both alphabets
/// assert_eq!(encode_char::<Latin26>(b'A'), Some(0));
/// assert_eq!(encode_char::<Latin36>(b'0'), Some(26));
/// ```
///
pub trait Alphabet {
    /// The number of characters in this alphabet.
    ///
    /// This constant defines the size of the alphabet, which is used for:
    /// - Array allocation and bounds checking
    /// - Modular arithmetic in cipher operations
    /// - Validation of normalized indices
    ///
    /// # Examples
    ///
    /// ```
    /// use old_crypto_rs::helpers::{Alphabet, Latin26, Latin36};
    ///
    /// assert_eq!(Latin26::SIZE, 26);
    /// assert_eq!(Latin36::SIZE, 36);
    /// ```
    ///
    const SIZE: usize;

    /// The alphabet itself
    ///
    /// This constant defines the list of used symbols/letters.
    ///
    const ALPHABET: &'static [u8];

    /// Converts a character to its 0-based index in the alphabet.
    ///
    /// This function takes a byte representing an ASCII character and returns its
    /// position in the alphabet as a 0-based index. Characters not in the alphabet
    /// return `None`.
    ///
    /// # Arguments
    ///
    /// * `ch` - An ASCII character byte to normalize
    ///
    /// # Returns
    ///
    /// - `Some(index)` - If the character is in the alphabet (0 to SIZE-1)
    /// - `None` - If the character is not supported by this alphabet
    ///
    /// # Examples
    ///
    /// ```
    /// use old_crypto_rs::helpers::{Alphabet, Latin26, Latin36};
    ///
    /// // Latin26: only uppercase letters
    /// assert_eq!(Latin26::normalize(b'A'), Some(0));
    /// assert_eq!(Latin26::normalize(b'Z'), Some(25));
    /// assert_eq!(Latin26::normalize(b'a'), Some(0)); // lowercase converted to uppercase
    /// assert_eq!(Latin26::normalize(b'0'), None); // digits not supported
    ///
    /// // Latin36: uppercase letters and digits
    /// assert_eq!(Latin36::normalize(b'A'), Some(0));
    /// assert_eq!(Latin36::normalize(b'Z'), Some(25));
    /// assert_eq!(Latin36::normalize(b'0'), Some(26));
    /// assert_eq!(Latin36::normalize(b'9'), Some(35));
    /// assert_eq!(Latin36::normalize(b'!'), None); // special chars not supported
    /// ```
    ///
    fn normalize(ch: u8) -> Option<usize>;

    /// Converts a 0-based alphabet index back to its corresponding character.
    ///
    /// This is the inverse operation of `normalize`. Given an index in the range
    /// [0, SIZE), it returns the corresponding ASCII character byte.
    ///
    /// # Arguments
    ///
    /// * `idx` - The 0-based index in the alphabet (should be < SIZE)
    ///
    /// # Returns
    ///
    /// The ASCII byte value of the character at the given index.
    ///
    /// # Panics
    ///
    /// Behavior is undefined if `idx >= SIZE`. Implementations may panic or return
    /// invalid results.
    ///
    /// # Examples
    ///
    /// ```
    /// use old_crypto_rs::helpers::{Alphabet, Latin26, Latin36};
    ///
    /// // Latin26: indices to uppercase letters
    /// assert_eq!(Latin26::denormalize(0), b'A');
    /// assert_eq!(Latin26::denormalize(25), b'Z');
    ///
    /// // Latin36: indices to letters and digits
    /// assert_eq!(Latin36::denormalize(0), b'A');
    /// assert_eq!(Latin36::denormalize(25), b'Z');
    /// assert_eq!(Latin36::denormalize(26), b'0');
    /// assert_eq!(Latin36::denormalize(35), b'9');
    /// ```
    ///
    fn denormalize(idx: usize) -> u8;
}

/// Implementation of the `Alphabet` trait for the standard 26-letter Latin alphabet (A-Z).
///
/// This implementation provides character encoding/decoding operations specifically for
/// uppercase English letters. It maps:
/// - 'A' to index 0
/// - 'B' to index 1
/// - ...
/// - 'Z' to index 25
///
/// Any characters outside the A-Z range (including lowercase letters, digits, and
/// special characters) are not supported and will return `None` from `normalize`.
///
/// # Examples
///
/// ```
/// use old_crypto_rs::helpers::{Alphabet, Latin26};
///
/// // Normalize uppercase letters
/// assert_eq!(Latin26::normalize(b'A'), Some(0));
/// assert_eq!(Latin26::normalize(b'M'), Some(12));
/// assert_eq!(Latin26::normalize(b'Z'), Some(25));
///
/// // Lowercase letters are converted to uppercase
/// assert_eq!(Latin26::normalize(b'a'), Some(0));
/// assert_eq!(Latin26::normalize(b'0'), None);
/// assert_eq!(Latin26::normalize(b' '), None);
///
/// // Denormalize indices back to letters
/// assert_eq!(Latin26::denormalize(0), b'A');
/// assert_eq!(Latin26::denormalize(12), b'M');
/// assert_eq!(Latin26::denormalize(25), b'Z');
/// ```
///
/// # See Also
///
/// * [`Latin36`] - Extended alphabet including digits
/// * [`Alphabet`] - The trait definition
///
impl Alphabet for Latin26 {
    const SIZE: usize = 26;
    const ALPHABET: &'static [u8] = b"ABCDEFGHIJKLMNOPQRSTUVXWYZ";

    fn normalize(ch: u8) -> Option<usize> {
        let ch = ch.to_ascii_uppercase();
        if ch.is_ascii_uppercase() {
            Some((ch - b'A') as usize)
        } else {
            None
        }
    }

    fn denormalize(idx: usize) -> u8 {
        b'A' + idx as u8
    }
}

/// Implementation of the `Alphabet` trait for the 25-letter Latin alphabet with I/J merger.
///
/// This implementation provides character encoding/decoding operations specifically for
/// a 25-character alphabet where 'I' and 'J' are treated as the same character. This
/// configuration is essential for classical ciphers that use a 5×5 grid structure.
///
/// # Character Mapping Strategy
///
/// The implementation uses a two-step normalization process:
/// 1. Map 'J' to 'I' (merge step)
/// 2. Calculate index with adjustment: letters after 'I' are shifted down by 1
///
/// This results in the following index mapping:
/// ```text
/// A B C D E F G H I/J K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z
/// 0 1 2 3 4 5 6 7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24
/// ```
///
/// Denormalization reverses this process, always producing 'I' for index 8, and
/// adding 1 to the character code for indices 9 and above to skip 'J'.
///
/// # Examples
///
/// ```
/// use old_crypto_rs::helpers::{Alphabet, Latin25};
///
/// // Basic normalization
/// assert_eq!(Latin25::normalize(b'A'), Some(0));
/// assert_eq!(Latin25::normalize(b'H'), Some(7));
///
/// // I/J merger - both normalize to index 8
/// assert_eq!(Latin25::normalize(b'I'), Some(8));
/// assert_eq!(Latin25::normalize(b'J'), Some(8));
///
/// // Letters after J are shifted down
/// assert_eq!(Latin25::normalize(b'K'), Some(9));
/// assert_eq!(Latin25::normalize(b'Z'), Some(24));
///
/// // Case insensitivity
/// assert_eq!(Latin25::normalize(b'a'), Some(0));
/// assert_eq!(Latin25::normalize(b'j'), Some(8));
///
/// // Non-letters return None
/// assert_eq!(Latin25::normalize(b'0'), None);
/// assert_eq!(Latin25::normalize(b'!'), None);
/// assert_eq!(Latin25::normalize(b' '), None);
///
/// // Denormalization always produces uppercase
/// assert_eq!(Latin25::denormalize(0), b'A');
/// assert_eq!(Latin25::denormalize(7), b'H');
/// assert_eq!(Latin25::denormalize(8), b'I'); // Note: 'I', not 'J'
/// assert_eq!(Latin25::denormalize(9), b'K');
/// assert_eq!(Latin25::denormalize(24), b'Z');
/// ```
///
/// # Usage in Ciphers
///
/// ```
/// use old_crypto_rs::helpers::{Alphabet, Latin25};
///
/// // Example: Encoding a message for Playfair cipher
/// fn encode_for_playfair(text: &str) -> Vec<usize> {
///     text.bytes()
///         .filter_map(|b| Latin25::normalize(b))
///         .collect()
/// }
///
/// let indices = encode_for_playfair("HELLO");
/// assert_eq!(indices, vec![7, 4, 10, 10, 13]); // H E L L O
///
/// // Note: "JELLO" would produce the same result as "IELLO"
/// let indices2 = encode_for_playfair("JELLO");
/// assert_eq!(indices2, vec![8, 4, 10, 10, 13]); // I/J E L L O
/// ```
///
/// # Performance
///
/// Time complexity: O(1) for both `normalize` and `denormalize`
/// Space complexity: O(1) - no allocations
///
/// # See Also
///
/// * [`Latin26`] - Standard 26-letter alphabet without merging
/// * [`Latin36`] - Extended alphabet including digits
/// * [`LatinSC`] - Regular alphabet with uppercase letters and 2 characters for straddling checkerboards.
/// * [`Alphabet`] - The trait definition
///
impl Alphabet for Latin25 {
    const SIZE: usize = 25;
    const ALPHABET: &'static [u8] = b"ABCDEFGHIKLMNOPQRSTUVXWYZ";

    fn normalize(ch: u8) -> Option<usize> {
        let ch = ch.to_ascii_uppercase();

        let mapped = match ch {
            b'J' => b'I',
            b'A'..=b'Z' => ch,
            _ => return None,
        };

        let idx = if mapped > b'I' {
            mapped - b'A' - 1
        } else {
            mapped - b'A'
        };

        Some(idx as usize)
    }

    fn denormalize(idx: usize) -> u8 {
        if idx > 8 {
            b'A' + idx as u8 + 1
        } else {
            b'A' + idx as u8
        }
    }
}

/// Implementation of the `Alphabet` trait for the extended 36-character alphanumeric alphabet.
///
/// This implementation provides character encoding/decoding operations for both uppercase
/// English letters (A-Z) and decimal digits (0-9). It maps:
/// - 'A' through 'Z' to indices 0-25
/// - '0' through '9' to indices 26-35
///
/// This encoding is useful for ciphers that need to handle both letters and numbers,
/// such as some variants of substitution ciphers or alphanumeric codes.
///
/// # Index Mapping
///
/// | Character Range | Index Range | Offset      |
/// |----------------|-------------|-------------|
/// | A-Z            | 0-25        | ch - 'A'    |
/// | 0-9            | 26-35       | 26 + (ch - '0') |
///
/// # Examples
///
/// ```
/// use old_crypto_rs::helpers::{Alphabet, Latin36};
///
/// // Normalize letters
/// assert_eq!(Latin36::normalize(b'A'), Some(0));
/// assert_eq!(Latin36::normalize(b'M'), Some(12));
/// assert_eq!(Latin36::normalize(b'Z'), Some(25));
///
/// // Normalize digits
/// assert_eq!(Latin36::normalize(b'0'), Some(26));
/// assert_eq!(Latin36::normalize(b'5'), Some(31));
/// assert_eq!(Latin36::normalize(b'9'), Some(35));
///
/// // Lowercase letters are converted to uppercase
/// assert_eq!(Latin36::normalize(b'a'), Some(0));
/// assert_eq!(Latin36::normalize(b' '), None);
/// assert_eq!(Latin36::normalize(b'!'), None);
///
/// // Denormalize indices to letters
/// assert_eq!(Latin36::denormalize(0), b'A');
/// assert_eq!(Latin36::denormalize(25), b'Z');
///
/// // Denormalize indices to digits
/// assert_eq!(Latin36::denormalize(26), b'0');
/// assert_eq!(Latin36::denormalize(35), b'9');
/// ```
///
/// # See Also
///
/// * [`Latin26`] - Standard 26-letter alphabet
/// * [`LatinSC`] - Regular alphabet with uppercase letters and 2 characters for straddling checkerboards.
/// * [`Alphabet`] - The trait definition
///
impl Alphabet for Latin36 {
    const SIZE: usize = 36;
    const ALPHABET: &'static [u8] = b"ABCDEFGHIJKLMNOPQRSTUVXWYZ0123456789";

    fn normalize(ch: u8) -> Option<usize> {
        let ch = ch.to_ascii_uppercase();
        if ch.is_ascii_uppercase() {
            Some((ch - b'A') as usize)
        } else if ch.is_ascii_digit() {
            Some(26 + (ch - b'0') as usize)
        } else {
            None
        }
    }

    fn denormalize(idx: usize) -> u8 {
        if idx < 26 {
            b'A' + idx as u8
        } else {
            b'0' + (idx - 26) as u8
        }
    }
}

/// Implementation of the `Alphabet` trait for the standard 26-letter Latin alphabet (A-Z) plus
/// two special characters, '-' and '/'.
///
/// This implementation provides character encoding/decoding operations specifically for
/// uppercase English letters. It maps:
/// - 'A' to index 0
/// - 'B' to index 1
/// - ...
/// - 'Z' to index 25
/// - '-' to index 26
/// - '/' to index 27
///
/// Any characters outside the A-Z range (including lowercase letters, digits, and
/// special characters) are not supported and will return `None` from `normalize`.
///
/// # Examples
///
/// ```
/// use old_crypto_rs::helpers::{Alphabet, LatinSC};
///
/// // Normalize uppercase letters
/// assert_eq!(Latin26::normalize(b'A'), Some(0));
/// assert_eq!(Latin26::normalize(b'M'), Some(12));
/// assert_eq!(Latin26::normalize(b'Z'), Some(25));
/// assert_eq!(Latin26::normalize(b'-'), Some(26));
///
/// // Lowercase letters are converted to uppercase
/// assert_eq!(Latin26::normalize(b'a'), Some(0));
/// assert_eq!(Latin26::normalize(b'0'), None);
/// assert_eq!(Latin26::normalize(b' '), None);
///
/// // Denormalize indices back to letters
/// assert_eq!(Latin26::denormalize(0), b'A');
/// assert_eq!(Latin26::denormalize(12), b'M');
/// assert_eq!(Latin26::denormalize(25), b'Z');
/// assert_eq!(Latin26::denormalize(27), b'/';
/// ```
///
/// # See Also
///
/// * [`Latin26`] - Regular alphabet with uppercase letters only
/// * [`Latin35`] - Regular alphabet with uppercase letters with I/J merged for 5x5 grid
/// * [`Latin36`] - Extended alphabet including digits
/// * [`Alphabet`] - The trait definition
///
impl Alphabet for LatinSC {
    const SIZE: usize = 28;
    const ALPHABET: &'static [u8] = SC_ALPHABET.as_bytes();

    fn normalize(ch: u8) -> Option<usize> {
        let ch = ch.to_ascii_uppercase();
        if ch.is_ascii_uppercase() {
            Some((ch - b'A') as usize)
        } else if ch == b'/' {
            Some(26)
        } else if ch == b'.' {
            Some(27)
        } else {
            None
        }
    }

    fn denormalize(idx: usize) -> u8 {
        if idx < 26 {
            b'A' + idx as u8
        } else if idx == 26 {
            b'/'
        } else {
            b'.'
        }
    }
}

/// Implementation of the `Alphabet` trait for the extended 36-character alphanumeric alphabet.
///
/// This implementation provides character encoding/decoding operations for both uppercase
/// English letters (A-Z) and decimal digits (0-9). It maps:
/// - 'A' through 'Z' to indices 0-25
/// - '*' as a word separator to index 26
/// - '0' through '9' to indices 27-36
/// - '/' to index 37
/// - '+' to index 38
///
/// This encoding is useful for ciphers that need to handle both letters and numbers,
/// such as some variants of substitution ciphers or alphanumeric codes.
///
/// # See Also
///
/// * [`Latin26`] - Standard 26-letter alphabet
/// * [`LatinSC`] - Regular alphabet with uppercase letters and 2 characters for straddling checkerboards.
/// * [`Alphabet`] - The trait definition
///
impl Alphabet for LatinSecom {
    const SIZE: usize = 39;
    const ALPHABET: &'static [u8] = b"ABCDEFGHIJKLMNOPQRSTUVXWYZ*0123456789/+";

    fn normalize(ch: u8) -> Option<usize> {
        let ch = ch.to_ascii_uppercase();
        if ch.is_ascii_uppercase() {
            Some((ch - b'A') as usize)
        } else if ch == b'*'{
            Some(26)
        } else if ch.is_ascii_digit() {
            Some(27 + (ch - b'0') as usize)
        } else if ch == b'/' {
            Some(37)
        } else if ch == b'+' {
            Some(38)
        } else {
            None
        }
    }

    fn denormalize(idx: usize) -> u8 {
        if idx < 26 {
            b'A' + idx as u8
        } else if idx == 26 {
            b'*'
        } else if idx < 37 {
            b'0' + (idx - 27) as u8
        } else if idx == 37 {
            b'/'
        } else {
            b'+'
        }
    }
}

