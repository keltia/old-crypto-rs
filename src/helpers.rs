//! A set of helpers functions.
//!
use std::collections::HashSet;

use eyre::Result;

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
pub struct Latin36;

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
    /// assert_eq!(Latin26::normalize(b'a'), None); // lowercase not supported
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
/// // Non-uppercase letters return None
/// assert_eq!(Latin26::normalize(b'a'), None);
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

    fn normalize(ch: u8) -> Option<usize> {
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
/// // Non-alphanumeric characters return None
/// assert_eq!(Latin36::normalize(b'a'), None);
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
/// * [`Alphabet`] - The trait definition
///
impl Alphabet for Latin36 {
    const SIZE: usize = 36;

    fn normalize(ch: u8) -> Option<usize> {
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

/// Removes all duplicate characters from a string, preserving the first occurrence of each.
///
/// This function iterates through the input string and builds a new string containing only
/// the first occurrence of each character, maintaining the original order. It uses a `HashSet`
/// to track which characters have already been encountered.
///
/// # Algorithm
///
/// 1. Create an empty `HashSet` to track seen characters
/// 2. Create an empty result `String`
/// 3. For each character in the input:
///    - If the character hasn't been seen (insert returns true), append it to the result
///    - If the character has been seen (insert returns false), skip it
/// 4. Return the result string
///
/// # Arguments
///
/// * `str` - A string slice to be condensed
///
/// # Returns
///
/// A new `String` with all duplicate characters removed, preserving the order of first occurrences
///
/// # Examples
///
/// ```
/// use old_crypto_rs::helpers::condense;
///
/// // Simple duplicates
/// let result = condense("AAAAA");
/// assert_eq!(result, "A");
///
/// // Mixed duplicates
/// let result = condense("ARABESQUE");
/// assert_eq!(result, "ARBESQU");
///
/// // Longer string with duplicates
/// let result = condense("ARABESQUEABCDEFGHIKLMNOPQRSTUVWXYZ");
/// assert_eq!(result, "ARBESQUCDFGHIKLMNOPTVWXYZ");
///
/// // No duplicates
/// let result = condense("ABCDE");
/// assert_eq!(result, "ABCDE");
/// ```
///
/// # Performance
///
/// Time complexity: O(n) where n is the length of the input string
/// Space complexity: O(k) where k is the number of unique characters
///
/// # See Also
///
/// * [`condense_str`] - An optimized version using a bitset for ASCII characters
///
pub fn condense(str: &str) -> String {
    let mut seen = HashSet::new();
    let mut condensed = String::new();

    for ch in str.chars() {
        if seen.insert(ch) {
            condensed.push(ch);
        }
    }
    condensed
}

/// Efficiently removes all duplicate characters from a string, returning a new String.
///
/// This implementation uses a bitset for ASCII characters to achieve O(n) time complexity
/// and minimal overhead.
///
pub fn condense_str(s: &str) -> String {
    let mut seen_ascii = [false; 256];
    let mut res = String::with_capacity(s.len());

    for c in s.chars() {
        if !seen_ascii[c as usize] {
            seen_ascii[c as usize] = true;
            res.push(c);
        }
    }
    res
}

/// insert one character inside the array
/// 
pub fn insert(src: &[u8], obj: u8, ind: usize) -> Vec<u8> {
    let mut dst = Vec::with_capacity(src.len() + 1);
    dst.extend_from_slice(&src[..ind]);
    dst.push(obj);
    dst.extend_from_slice(&src[ind..]);
    dst.to_vec()
}

/// Expands a byte slice by inserting 'X' between consecutive duplicate characters.
///
/// This function processes the input in pairs (digrams), inserting the byte `b'X'`
/// between any two consecutive identical characters. This is commonly used in
/// classical ciphers like Playfair to ensure all digrams consist of different characters.
///
/// # Algorithm
///
/// 1. Copy the source slice into a mutable vector
/// 2. Iterate through the vector in steps of 2 (processing digrams)
/// 3. If two consecutive characters are identical, insert `b'X'` between them
/// 4. Continue processing, which causes the inserted 'X' to become part of the next digram
///
/// # Arguments
///
/// * `src` - A byte slice to be expanded
///
/// # Returns
///
/// A new `Vec<u8>` with 'X' characters inserted between consecutive duplicates
///
/// # Examples
///
/// ```
/// use old_crypto_rs::helpers::expand;
///
/// // Simple duplicate
/// let input = b"AAA";
/// let result = expand(input);
/// assert_eq!(result, b"AXAXA");
///
/// // No duplicates
/// let input = b"ARABESQUE";
/// let result = expand(input);
/// assert_eq!(result, b"ARABESQUE");
///
/// // Multiple consecutive duplicates
/// let input = b"AAAA";
/// let result = expand(input);
/// assert_eq!(result, b"AXAXAXA");
///
/// // Duplicates in different positions
/// let input = b"LANNONCE";
/// let result = expand(input);
/// assert_eq!(result, b"LANXNONCE");
/// ```
///
/// # Performance
///
/// Time complexity: O(n) where n is the length of the input, though insertions may cause
/// reallocation in worst case scenarios with many consecutive duplicates.
/// Space complexity: O(n + k) where k is the number of 'X' characters inserted.
///
/// # See Also
///
/// * [`insert`] - The helper function used to insert characters
///
pub fn expand(src: &[u8]) -> Vec<u8> {
    let mut res = src.to_vec();
    let mut i = 0;
    while i < res.len().saturating_sub(1) {
        if res[i] == res[i + 1] {
            res = insert(&res, b'X', i + 1);
        }
        i += 2;
    }
    res
}

/// The 26-letter alphabet we know and love in the Western part of the world
pub const REGULAR_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Default alphabet containing A-Z plus special characters '/' and '-'.
/// The '/' character is used as a digit escape marker in encryption.
pub const SC_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ/-";

/*
  # Form an alphabet formed with a keyword, re-shuffle everything to
  # make it less predictable (i.e. checkerboard effect)
  #
  # Shuffle the alphabet a bit to avoid sequential allocation of the
  # code numbers.  This is actually performing a transposition with the word
  # itself as key.
  #
  # Regular rectangle
  # -----------------
  # Key is ARABESQUE condensed into ARBESQU (len = 7) (height = 4)
  # Let word be ARBESQUCDFGHIJKLMNOPTVWXYZ/-
  #
  # First passes will generate
  #
  # A  RBESQUCDFGHIJKLMNOPTVWXYZ/-   c=0  0 x 6
  # AC  RBESQUDFGHIJKLMNOPTVWXYZ/-   c=6  1 x 6
  # ACK  RBESQUDFGHIJLMNOPTVWXYZ/-   c=12 2 x 6
  # ACKV  RBESQUDFGHIJLMNOPTWXYZ/-   c=18 3 x 6
  # ACKVR  BESQUDFGHIJLMNOPTWXYZ/-   c=0  0 x 5
  # ACKVRD  BESQUFGHIJLMNOPTWXYZ/-   c=5  1 x 5
  # ...
  # ACKVRDLWBFMXEGNYSHOZQIP/UJT-
  #
  # Irregular rectangle
  # -------------------
  # Key is SUBWAY condensed info SUBWAY (len = 6) (height = 5)
  #
  # S  UBWAYCDEFGHIJKLMNOPQRTVXZ/-   c=0  0 x 5
  # SC  UBWAYDEFGHIJKLMNOPQRTVXZ/-   c=5  1 x 5
  # SCI  UBWAYDEFGHJKLMNOPQRTVXZ/-   c=10 2 x 5
  # SCIO  UBWAYDEFGHJKLMNPQRTVXZ/-   c=15 3 x 5
  # SCIOX  UBWAYDEFGHJKLMNPQRTVZ/-   c=20 4 x 5
  # SCIOXU  BWAYDEFGHJKLMNPQRTVZ/-   c=0  0 x 4
  # ...
  # SCIOXUDJPZBEKQ/WFLR-AG  YHMNTV   c=1  1 x 1
  # SCIOXUDJPZBEKQ/WFLR-AGM  YHNTV   c=2  2 x 1
  # SCIOXUDJPZBEKQ/WFLR-AGMT  YHNV   c=3  3 x 1
  # SCIOXUDJPZBEKQ/WFLR-AGMTYHNV
*/

/// Shuffles an alphabet using a keyword to create a mixed alphabet for cipher use.
///
/// # Algorithm
///
/// 1. Condense the concatenation of `key` and `alphabet` to remove duplicates
/// 2. Calculate dimensions: `length` = condensed key length, `height` = alphabet length / length
/// 3. Extract characters in a specific pattern based on these dimensions, working backwards
///    through columns and forwards through rows
///
/// # Arguments
///
/// * `key` - The keyword used to shuffle the alphabet (will be condensed to remove duplicates)
/// * `alphabet` - The alphabet string to be shuffled
///
/// # Returns
///
/// A new `String` containing the shuffled alphabet
///
/// # Examples
///
/// Regular rectangle (key length divides alphabet evenly):
/// ```
/// use old_crypto_rs::helpers::shuffle;
///
/// let key = "ARABESQUE";  // Condenses to "ARBESQU" (length = 7)
/// let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ/-";  // 28 chars, height = 4
/// let result = shuffle(key, alphabet);
/// assert_eq!(result, "ACKVRDLWBFMXEGNYSHOZQIP/UJT-");
/// ```
///
/// Irregular rectangle (key length does not divide alphabet evenly):
/// ```
/// use old_crypto_rs::helpers::shuffle;
///
/// let key = "SUBWAY";  // Condenses to "SUBWAY" (length = 6)
/// let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ/-";  // 28 chars, height = 5
/// let result = shuffle(key, alphabet);
/// assert_eq!(result, "SCIOXUDJPZBEKQ/WFLR-AGMTYHNV");
/// ```
///
/// # Performance
///
/// Time complexity: O(n * m) where n is the key length and m is the height
/// Space complexity: O(n + m) for the working vector and result string
///
pub fn shuffle(key: &str, alphabet: &str) -> String {
    let mut word = Vec::with_capacity(key.len() + alphabet.len());
    let mut seen = [false; 256];
    let mut length = 0;
    for c in key.chars() {
        if (c as usize) < 256 && !seen[c as usize] {
            seen[c as usize] = true;
            word.push(c as u8);
            length += 1;
        }
    }
    if length == 0 {
        return alphabet.to_string();
    }

    for c in alphabet.chars() {
        if (c as usize) < 256 && !seen[c as usize] {
            seen[c as usize] = true;
            word.push(c as u8);
        }
    }

    let mut height = alphabet.len() / length;
    if alphabet.len() % length != 0 {
        height += 1;
    }

    let mut res = String::with_capacity(word.len());
    for i in (0..length).rev() {
        for j in 0..=height {
            if word.len() <= height.saturating_sub(1) {
                res.push_str(std::str::from_utf8(&word).unwrap());
                return res;
            } else {
                if i * j < word.len() {
                    let c = word.remove(i * j);
                    res.push(c as char);
                }
            }
        }
    }
    res
}

/// Shuffles an alphabet using a keyword to create a mixed alphabet for cipher use.
///
/// BTW: the transposition comment about `shuffle` was coming from the Go version...
/// and is wrong.
///
/// The main issue with  plain `shuffle()` is that the first letter in the final
/// alphabet is always the same as the key.  This version does not have this problem.
///
/// This optimized version performs transposition directly without creating intermediate
/// objects, making it as fast as the plain shuffle, if not faster.
///
/// inlining FTW :)
///
/// # Benchmark
/// PC, AMD 7700X 3.60GHz, 16GB RAM, Win 11 25H2
/// ```text
/// Timer precision: 100 ns
/// shuffle                  fastest       │ slowest       │ median        │ mean          │ samples │ iters
/// ├─ bench_shuffle         377.9 ns      │ 696.6 ns      │ 393.5 ns      │ 395 ns        │ 100     │ 3200
/// ╰─ bench_transp_shuffle  243.5 ns      │ 273.2 ns      │ 246.6 ns      │ 252 ns        │ 100     │ 6400
/// ```
///
pub fn transp_shuffle(key: &str, alphabet: &str) -> Result<String> {
    // Short-circuit if key is empty
    //
    if key.is_empty() {
        return Ok(alphabet.to_string());
    }

    // Condense key inline using bitset (same as shuffle())
    //
    let mut seen = [false; 256];
    let mut condensed_key = Vec::with_capacity(key.len());
    for c in key.chars() {
        if (c as usize) < 256 && !seen[c as usize] {
            seen[c as usize] = true;
            condensed_key.push(c as u8);
        }
    }

    // Compute numeric key inline (to_numeric equivalent)
    //
    let klen = condensed_key.len();
    let mut indexed: Vec<(usize, u8)> = condensed_key.iter().enumerate().map(|(i, &b)| (i, b)).collect();
    indexed.sort_unstable_by_key(|&(_, b)| b);

    let mut tkey = vec![0u8; klen];
    for (rank, (original_idx, _)) in indexed.into_iter().enumerate() {
        tkey[original_idx] = rank as u8;
    }

    // Precompute column positions to avoid repeated searches
    //
    let mut col_positions = vec![0usize; klen];
    for i in 0..klen {
        col_positions[i] = tkey.iter().position(|&x| x == i as u8).unwrap();
    }

    // Perform transposition directly into String
    //
    let src = alphabet.as_bytes();
    let mut result = Vec::with_capacity(alphabet.len());

    // Build the result
    //
    for &j in &col_positions {
        let mut curr = j;
        while curr < src.len() {
            result.push(src[curr]);
            curr += klen;
        }
    }

    Ok(String::from_utf8(result)?)
}

/// Converts a string key into a numeric representation based on alphabetical order.
///
/// This function is commonly used to derive numeric keys for transposition ciphers.
/// It assigns a rank to each character in the key based on its Unicode scalar value.
/// If characters are identical, their original positions determine their relative rank.
///
/// # Arguments
///
/// * `key` - The string slice to be converted.
///
/// # Returns
///
/// A `Vec<u8>` where each element corresponds to the alphabetical rank (0-indexed)
/// of the character at that position in the original string.
///
/// # Examples
///
/// ```
/// use old_crypto_rs::helpers::to_numeric;
///
/// let key = "ZEBRAS";
/// let numeric = to_numeric(key);
/// // A=0, B=1, E=2, R=3, S=4, Z=5
/// // Z (5), E (2), B (1), R (3), A (0), S (4)
/// assert_eq!(numeric, vec![5, 2, 1, 3, 0, 4]);
/// ```
///
pub fn to_numeric(key: &str) -> Vec<u8> {
    let letters = key.as_bytes();
    let mut indexed: Vec<(usize, u8)> = letters.iter().enumerate().map(|(i, &b)| (i, b)).collect();
    indexed.sort_by_key(|&(_, b)| b);

    let mut ar = vec![0u8; letters.len()];
    for (rank, (original_idx, _)) in indexed.into_iter().enumerate() {
        ar[original_idx] = rank as u8;
    }
    ar
}

/// Inserts a space every `n` characters in a string.
///
/// This is typically used to format ciphertext into readable blocks.
///
/// # Arguments
///
/// * `ct` - The input string slice.
/// * `n` - The number of characters in each block.
///
/// # Returns
///
/// A new `String` with spaces inserted every `n` characters.
///
/// # Examples
///
/// ```
/// use old_crypto_rs::helpers::by_n;
///
/// let input = "ABCDEFGHIJ";
/// let result = by_n(input, 5);
/// assert_eq!(result, "ABCDE FGHIJ");
/// ```
///
pub fn by_n(ct: &str, n: usize) -> String {
    let mut out = String::new();
    let mut count = 0;
    for ch in ct.chars() {
        if count > 0 && count % n == 0 {
            out.push(' ');
        }
        out.push(ch);
        count += 1;
    }
    out
}

/// Formats a string into blocks of 5 characters separated by spaces.
///
/// This function takes a string slice and returns a new `String` where a space
/// is inserted every 5 characters.
///
/// # Arguments
///
/// * `input` - A string slice to be formatted
///
/// # Returns
///
/// A new `String` with spaces inserted every 5 characters.
pub fn output_as_block(input: &str) -> String {
    by_n(input, 5)
}

/// Replaces consecutive identical characters by inserting a fill character between them.
///
/// For example, "AA" becomes "AQA" if the fill character is 'Q'. This is often used
/// in classical ciphers to handle double letters.
///
/// >NOTE: this function works regardless of alignment; that is, it does not check if the double
/// letters are on a 2-character boundary.  Therefore, it is useless for `Playfair`, or any
/// bi-grammatic ciphers.
///
/// e.g.
/// HELLOWORLD -> HE LX LO WO RL DX
/// but  also
/// CETOOTEST -> CE TO XO TE ST
///
/// # Arguments
///
/// * `str` - The input string to process.
/// * `fill` - The character to insert between identical consecutive characters.
///
/// # Returns
///
/// A new `String` with the fill character inserted where necessary.
///
pub fn fix_double(str: &str, fill: char) -> String {
    let mut fixed = String::with_capacity(str.len());
    let mut chars = str.chars();

    if let Some(first) = chars.next() {
        fixed.push(first);
        let mut prev = first;
        for ch in chars {
            if ch == prev {
                fixed.push(fill);
            }
            fixed.push(ch);
            prev = ch;
        }
    }

    fixed
}

/// Replaces consecutive identical characters by inserting a fill character between them,
/// but only when the duplicate pair falls on a 2-character boundary.
///
/// This function is specifically designed for bi-grammatic ciphers like Playfair, where
/// doubles must be fixed only if they would form a single digram (2-character block).
///
/// Unlike `fix_double`, this function respects alignment. It processes the string in
/// 2-character chunks and only inserts the fill character when both characters in a
/// digram are identical.
///
/// e.g.
/// HELLOWORLD -> HE LX LO WO RL DX (LL becomes LX, DD becomes DX)
/// CETOOTEST  -> CE TO OT ES TX (OO is on boundary, so no change needed as they're in different digrams)
///
/// # Arguments
///
/// * `str` - The input string to process.
/// * `fill` - The character to insert between identical characters in the same digram.
///
/// # Returns
///
/// A new `String` with the fill character inserted where necessary, respecting 2-character boundaries.
///
pub fn fix_double_aligned(str: &str, fill: char) -> String {
    let chars: Vec<char> = str.chars().collect();
    let mut fixed = String::with_capacity(str.len());
    let mut i = 0;

    while i < chars.len() {
        if i + 1 < chars.len() && chars[i] == chars[i + 1] {
            // Double on boundary - insert fill character
            fixed.push(chars[i]);
            fixed.push(fill);
            i += 1; // Move forward by 1, so the second character becomes part of next digram
        } else if i + 1 < chars.len() {
            // Normal digram - add both characters
            fixed.push(chars[i]);
            fixed.push(chars[i + 1]);
            i += 2;
        } else {
            // Last character (odd length)
            fixed.push(chars[i]);
            i += 1;
        }
    }

    fixed
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    #[case("ABCDE", "ABCDE")]
    #[case("AAAAA", "A")]
    #[case("ARABESQUE", "ARBESQU")]
    #[case("ARABESQUEABCDEFGHIKLMNOPQRSTUVWXYZ", "ARBESQUCDFGHIKLMNOPTVWXYZ")]
    #[case("PLAYFAIRABCDEFGHIKLMNOPQRSTUVWXYZ", "PLAYFIRBCDEGHKMNOQSTUVWXZ")]
    #[case("PLAYFAIREXMABCDEFGHIKLMNOPQRSTUVWXYZ", "PLAYFIREXMBCDGHKNOQSTUVWZ")]
    fn test_condense(#[case] in_str: &str, #[case] expected: &str) {
        assert_eq!(condense(in_str), expected);
    }

    #[rstest]
    #[case("AAA", "AXAXA")]
    #[case("AAAA", "AXAXAXA")]
    #[case("AAABRAACADAABRA", "AXAXABRAACADAXABRA")]
    #[case("ARABESQUE", "ARABESQUE")]
    #[case("LANNONCE", "LANXNONCE")]
    #[case("PJRJJJJJJS", "PJRJJXJXJXJXJS")]
    #[case("ABCDEFGHJJKLM", "ABCDEFGHJXJKLM")]
    fn test_expand_insert(#[case] in_str: &str, #[case] expected: &str) {
        assert_eq!(expand(in_str.as_bytes()), expected.as_bytes());
    }

    #[test]
    fn test_insert() {
        let a = [0, 1, 2, 3];
        let b = [0, 1, 42, 2, 3];
        assert_eq!(insert(&a, 42, 2), b);
    }

    #[rstest]
    #[case("ARABESQUE", "ACKVRDLWBFMXEGNYSHOZQIP/UJT-")]
    #[case("SUBWAY", "SCIOXUDJPZBEKQ/WFLR-AGMTYHNV")]
    fn test_shuffle(#[case] key: &str, #[case] expected: &str) {
        let res = shuffle(key, SC_ALPHABET);
        assert_eq!(res, expected);
    }

    #[rstest]
    #[case("ARABESQUE", "AHOVCJQXDKRYFMT/BIPWELSZGNU-")]
    #[case("SUBWAY", "EKQWCIOU/AGMSYBHNTZDJPV-FLRX")]
    fn test_transp_shuffle(#[case] key: &str, #[case] expected: &str) {
        let res = transp_shuffle(key, SC_ALPHABET);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res, expected);
    }

    #[rstest]
    #[case("ARABESQUE", vec![0, 6, 1, 2, 3, 7, 5, 8, 4])]
    #[case("PJRJJJJJJS", vec![7, 0, 8, 1, 2, 3, 4, 5, 6, 9])]
    #[case("AAABRAACADAABRA", vec![0, 1, 2, 9, 13, 3, 4, 11, 5, 12, 6, 7, 10, 14, 8])]
    fn test_to_numeric(#[case] key: &str, #[case] expected: Vec<u8>) {
        assert_eq!(to_numeric(key), expected);
    }

    #[rstest]
    #[case(5, "ARABESQUE", "ARABE SQUE")]
    #[case(4, "PJRJJJJJJS", "PJRJ JJJJ JS")]
    #[case(5, "AAABRAACADAABRA", "AAABR AACAD AABRA")]
    fn test_by_n(#[case] n: usize, #[case] in_str: &str, #[case] expected: &str) {
        assert_eq!(by_n(in_str, n), expected);
    }

    #[rstest]
    #[case("ARABESQUE", "ARABE SQUE")]
    #[case("PJRJJJJJJS", "PJRJJ JJJJS")]
    #[case("AAABRAACADAABRA", "AAABR AACAD AABRA")]
    #[case("ABCDE", "ABCDE")]
    #[case("ABCDEF", "ABCDE F")]
    fn test_output_as_block(#[case] in_str: &str, #[case] expected: &str) {
        assert_eq!(output_as_block(in_str), expected);
    }

    #[rstest]
    #[case('Q', "ABCDEF", "ABCDEF")]
    #[case('Q', "AABCDE", "AQABCDE")]
    #[case('Q', "AAAAA", "AQAQAQAQA")]
    #[case('Q', "CETOOT", "CETOQOT")]
    #[case('Q', "CETOOTESTCHIFFREAVEC", "CETOQOTESTCHIFQFREAVEC")]
    #[case('X', "ABCDEF", "ABCDEF")]
    #[case('X', "AABCDE", "AXABCDE")]
    #[case('X', "AAAAA", "AXAXAXAXA")]
    #[case('X', "CETOOT", "CETOXOT")]
    #[case('X', "CETOOTESTCHIFFREAVEC", "CETOXOTESTCHIFXFREAVEC")]
    fn test_fix_double(#[case] fill: char, #[case] in_str: &str, #[case] expected: &str) {
        assert_eq!(fix_double(in_str, fill), expected);
    }

    #[rstest]
    #[case('Q', "ABCDEF", "ABCDEF")]
    #[case('Q', "AABCDE", "AQABCDE")]
    #[case('Q', "AAAAA", "AQAQAQAQA")] // AA -> AQ A, AA -> AQ A, AA -> AQ A
    #[case('Q', "CETOOT", "CETOOT")]   // CE TO OT becomes CE TO QO T
    #[case('Q', "HELLOWORLD", "HELQLOWORLD")] // LL on boundary becomes LQ
    #[case('Q', "CETOOTEST", "CETOOTEST")] // OO is split across digrams (O|O), so no change
    #[case('X', "ABCDEF", "ABCDEF")]
    #[case('X', "AABCDE", "AXABCDE")]
    #[case('X', "AAAAA", "AXAXAXAXA")]
    #[case('X', "CETOOT", "CETOOT")]
    #[case('X', "HELLOWORLD", "HELXLOWORLD")]
    #[case('X', "CETOOTEST", "CETOOTEST")] // OO is split across digrams
    fn test_fix_double_aligned(#[case] fill: char, #[case] in_str: &str, #[case] expected: &str) {
        assert_eq!(fix_double_aligned(in_str, fill), expected);
    }
}
