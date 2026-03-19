use crate::{Block, Transposition};
use std::collections::HashSet;

use eyre::Result;

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
/// alphabet is always the same as the key.  This version does not have this problem
/// but is slower.
///
/// cf.
/// ```text
/// cargo bench --bench shuffle`
///
/// Timer precision: 100 ns
/// shuffle                  fastest       │ slowest       │ median        │ mean          │ samples │ iters
/// ├─ bench_shuffle         135.7 ns      │ 168.5 ns      │ 136.5 ns      │ 136.9 ns      │ 100     │ 12800
/// ╰─ bench_transp_shuffle  352.9 ns      │ 718.5 ns      │ 393.5 ns      │ 407.7 ns      │ 100     │ 3200
/// ```
///
/// So, to void the issue, implement shuffle as a transposition of the alphabet using
/// the key.
///
pub fn transp_shuffle(key: &str, alphabet: &str) -> Result<String> {
    let key = condense(key);
    let tr = Transposition::new(&key)?;

    let fixpt = alphabet.as_bytes();
    let mut dst = vec![0u8; alphabet.len()];
    let _ = tr.encrypt(&mut dst, fixpt);
    Ok(String::from_utf8(dst)?)
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
