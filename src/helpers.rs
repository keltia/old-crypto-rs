use std::collections::HashSet;

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
/// This function combines a keyword with an alphabet, removes duplicates, then performs
/// a transposition using the keyword itself as the key. This creates a less predictable
/// arrangement (checkerboard effect) suitable for use in classical ciphers.
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
/// let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ/-";  // 29 chars, height = 5
/// let result = shuffle(key, alphabet);
/// assert_eq!(result, "ACKVRDLWBFMXEGNYSHOZQIP/UJT-");
/// ```
///
/// Irregular rectangle (key length does not divide alphabet evenly):
/// ```
/// use old_crypto_rs::helpers::shuffle;
///
/// let key = "SUBWAY";  // Condenses to "SUBWAY" (length = 6)
/// let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ/-";  // 29 chars, height = 5
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
    let mut word: Vec<u8> = condense(&format!("{}{}", key, alphabet)).into_bytes();
    let length = condense(key).len();

    let mut height = alphabet.len() / length;
    if alphabet.len() % length != 0 {
        height += 1;
    }

    let mut res = String::new();
    for i in (0..length).rev() {
        for j in 0..=height {
            if word.len() <= height.saturating_sub(1) {
                res.push_str(&String::from_utf8_lossy(&word));
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

/// Optimized version of shuffle that uses index tracking instead of vector removals.
///
/// This function provides the same functionality as `shuffle` but with better performance
/// by using a boolean array to track used characters instead of repeatedly removing elements
/// from a vector, which causes O(n) shifts on each removal.
///
/// # Performance
///
/// Time complexity: O(n * m) where n is the key length and m is the height (same as shuffle)
/// However, the constant factor is much better due to avoiding vector element removals.
/// Space complexity: O(n + m) for the working vector, result string, and used array
///
/// # Examples
///
/// ```
/// use old_crypto_rs::helpers::shuffle_next;
///
/// let key = "ARABESQUE";
/// let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ/-";
/// let result = shuffle_next(key, alphabet);
/// assert_eq!(result, "ACKVRDLWBFMXEGNYSHOZQIP/UJT-");
/// ```
///
/// # See Also
///
/// * [`shuffle`] - The original implementation
///
pub fn shuffle_next(key: &str, alphabet: &str) -> String {
    let word: Vec<u8> = condense(&format!("{}{}", key, alphabet)).into_bytes();
    let length = condense(key).len();

    let mut height = alphabet.len() / length;
    if alphabet.len() % length != 0 {
        height += 1;
    }

    let mut res = String::new();
    let mut used = vec![false; word.len()];
    let mut remaining = word.len();

    for i in (0..length).rev() {
        for j in 0..=height {
            if remaining <= height.saturating_sub(1) {
                for (idx, &ch) in word.iter().enumerate() {
                    if !used[idx] {
                        res.push(ch as char);
                    }
                }
                return res;
            } else {
                let target_index = i * j;
                if target_index < remaining {
                    let mut actual_index = 0;
                    let mut count = 0;
                    for (idx, &is_used) in used.iter().enumerate() {
                        if !is_used {
                            if count == target_index {
                                actual_index = idx;
                                break;
                            }
                            count += 1;
                        }
                    }

                    res.push(word[actual_index] as char);
                    used[actual_index] = true;
                    remaining -= 1;
                }
            }
        }
    }
    res
}

pub fn to_numeric(key: &str) -> Vec<u8> {
    let letters = key.as_bytes();
    let mut sorted = letters.to_vec();
    sorted.sort_unstable();

    let mut used_sorted = vec![false; sorted.len()];
    let mut ar = Vec::with_capacity(letters.len());

    for &ch in letters {
        for (k, &s_ch) in sorted.iter().enumerate() {
            if s_ch == ch && !used_sorted[k] {
                ar.push(k as u8);
                used_sorted[k] = true;
                break;
            }
        }
    }
    ar
}

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

/// Replace all instance of NN with NQN
pub fn fix_double(str: &str, fill: char) -> String {
    let mut fixed = String::new();
    let mut prev = None;
    for ch in str.chars() {
        if let Some(p) = prev {
            if ch == p {
                fixed.push(fill);
            }
        }
        fixed.push(ch);
        prev = Some(ch);
    }
    fixed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_condense() {
        let test_data = [
            ("ABCDE", "ABCDE"),
            ("AAAAA", "A"),
            ("ARABESQUE", "ARBESQU"),
            ("ARABESQUEABCDEFGHIKLMNOPQRSTUVWXYZ", "ARBESQUCDFGHIKLMNOPTVWXYZ"),
            ("PLAYFAIRABCDEFGHIKLMNOPQRSTUVWXYZ", "PLAYFIRBCDEGHKMNOQSTUVWXZ"),
            ("PLAYFAIREXMABCDEFGHIKLMNOPQRSTUVWXYZ", "PLAYFIREXMBCDGHKNOQSTUVWZ"),
        ];
        for (a, b) in test_data {
            assert_eq!(condense(a), b);
        }
    }

    #[test]
    fn test_expand_insert() {
        let test_data = [
            ("AAA", "AXAXA"),
            ("AAAA", "AXAXAXA"),
            ("AAABRAACADAABRA", "AXAXABRAACADAXABRA"),
            ("ARABESQUE", "ARABESQUE"),
            ("LANNONCE", "LANXNONCE"),
            ("PJRJJJJJJS", "PJRJJXJXJXJXJS"),
            ("ABCDEFGHJJKLM", "ABCDEFGHJXJKLM"),
        ];
        for (a, b) in test_data {
            assert_eq!(expand(a.as_bytes()), b.as_bytes());
        }
    }

    #[test]
    fn test_insert() {
        let a = [0, 1, 2, 3];
        let b = [0, 1, 42, 2, 3];
        assert_eq!(insert(&a, 42, 2), b);
    }

    #[test]
    fn test_shuffle() {
        let key = "ARABESQUE";
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ/-";
        let res = shuffle(key, alphabet);
        assert_eq!(res, "ACKVRDLWBFMXEGNYSHOZQIP/UJT-");
    }

    #[test]
    fn test_shuffle_odd() {
        let key = "SUBWAY";
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ/-";
        let res = shuffle(key, alphabet);
        assert_eq!(res, "SCIOXUDJPZBEKQ/WFLR-AGMTYHNV");
    }

    #[test]
    fn test_shuffle_next() {
        let key = "ARABESQUE";
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ/-";
        let res = shuffle_next(key, alphabet);
        assert_eq!(res, "ACKVRDLWBFMXEGNYSHOZQIP/UJT-");
    }

    #[test]
    fn test_shuffle_next_odd() {
        let key = "SUBWAY";
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ/-";
        let res = shuffle_next(key, alphabet);
        assert_eq!(res, "SCIOXUDJPZBEKQ/WFLR-AGMTYHNV");
    }

    #[test]
    fn test_to_numeric() {
        let test_data = [
            ("ARABESQUE", vec![0, 6, 1, 2, 3, 7, 5, 8, 4]),
            ("PJRJJJJJJS", vec![7, 0, 8, 1, 2, 3, 4, 5, 6, 9]),
            ("AAABRAACADAABRA", vec![0, 1, 2, 9, 13, 3, 4, 11, 5, 12, 6, 7, 10, 14, 8]),
        ];
        for (str, key) in test_data {
            assert_eq!(to_numeric(str), key);
        }
    }

    #[test]
    fn test_by_n() {
        let test_data = [
            (5, "ARABESQUE", "ARABE SQUE"),
            (4, "PJRJJJJJJS", "PJRJ JJJJ JS"),
            (5, "AAABRAACADAABRA", "AAABR AACAD AABRA"),
        ];
        for (n, in_str, out_str) in test_data {
            assert_eq!(by_n(in_str, n), out_str);
        }
    }

    #[test]
    fn test_output_as_block() {
        let test_data = [
            ("ARABESQUE", "ARABE SQUE"),
            ("AAABRAACADAABRA", "AAABR AACAD AABRA"),
            ("ABCDE", "ABCDE"),
            ("ABCDEF", "ABCDE F"),
        ];
        for (in_str, out_str) in test_data {
            assert_eq!(output_as_block(in_str), out_str);
        }
    }

    #[test]
    fn test_fix_double() {
        let test_data = [
            ("ABCDEF", "ABCDEF"),
            ("AABCDE", "AQABCDE"),
            ("AAAAA", "AQAQAQAQA"),
        ];
        for (in_str, out_str) in test_data {
            assert_eq!(fix_double(in_str, 'Q'), out_str);
        }
    }
}
