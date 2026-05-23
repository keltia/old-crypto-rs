use smallvec::SmallVec;

/// Some useful types, using the smallvec 1.x API.
///
pub type Digits10 = SmallVec<[u8; 10]>;
pub type Digits16 = SmallVec<[u8;16]>;
pub type Order16 = SmallVec<[usize; 16]>;
pub type Indexed16 = SmallVec<[(usize, u8); 16]>;

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
pub fn to_numeric_old(key: &str) -> Vec<u8> {
    let letters = key.as_bytes();
    let mut indexed: Vec<(usize, u8)> = letters.iter().enumerate().map(|(i, &b)| (i, b)).collect();
    indexed.sort_by_key(|&(_, b)| b);

    let mut ar = vec![0u8; letters.len()];
    for (rank, (original_idx, _)) in indexed.into_iter().enumerate() {
        ar[original_idx] = rank as u8;
    }
    ar
}

/// This is `to_numeric`, but 1-based for digits:
/// '1' ranks first, ..., '9' ranks ninth, and '0' ranks tenth.
///
/// Duplicate digits are ranked left-to-right because `sort_by_key` is stable.
///
pub fn to_numeric_one_old(s: &str) -> Vec<u8> {
    fn digit_rank(b: u8) -> u8 {
        match b {
            b'1'..=b'9' => b - b'0', // 1..=9
            b'0' => 10,
            _ => b, // fallback for non-digits, useful for phrase text
        }
    }

    let s = s.as_bytes();

    let mut indexed: Vec<(usize, u8)> = s
        .iter()
        .enumerate()
        .map(|(i, &b)| (i, b))
        .collect();

    indexed.sort_by_key(|&(_, b)| digit_rank(b));

    let mut ar = vec![0u8; s.len()];

    for (rank, (original_idx, _)) in indexed.into_iter().enumerate() {
        ar[original_idx] = ((rank + 1) % 10) as u8;
    }

    ar
}

/// Transforms a string into a vector of numeric values based on a specified key function.
///
/// This function processes a string `s` by first mapping each character byte to a numeric value
/// using the provided key function `key`. It then sorts the byte indices based on the output of
/// the key function and assigns a numeric ranking to each character position in the original string.
///
/// # Parameters
/// - `s`: A string slice (`&str`) to be processed.
/// - `key`: A closure or function (`Fn(u8) -> u8`) that takes a character byte and returns a numeric key
///   to determine the sort order.
/// - `one_based_mod10`: A boolean flag that determines the numeric ranking method:
///   - If `true`, the rankings are one-based and take modulo 10 (e.g., `1, 2, ..., 9, 0, 1, ...`).
///   - If `false`, the rankings are zero-based (e.g., `0, 1, 2, ...`).
///
/// # Returns
/// A `Vec<u8>` containing the numeric values for each character in the original string,
/// ordered by their positions in `s`. Each numeric value represents the ranking of the
/// character based on the `key` function.
///
/// # Example
/// ```
/// let input = "dcba";
/// // Sorts characters by their ASCII values
/// let result = numeric_by_key(input, |b| b, true);
/// assert_eq!(result, vec![4, 3, 2, 1]); // Rankings modulo 10, one-based
///
/// let result = numeric_by_key(input, |b| b, false);
/// assert_eq!(result, vec![3, 2, 1, 0]); // Rankings zero-based
/// ```
///
/// # Notes
/// - The function assumes that `s` contains only ASCII-compatible characters.
/// - The use of one-based modulo 10 rankings can be particularly useful for certain
///   encoding or hashing scenarios.
///
/// # Type Aliases Used
/// - `Indexed16`: A type alias for collecting enumerated byte indices from `s`.
/// - `Digits16`: A type alias for a collection (initially allocated but resized)
///   that stores numeric rankings.
///
fn numeric_by_key<F>(s: &str, key: F, one_based_mod10: bool) -> Vec<u8>
where
    F: Fn(u8) -> u8,
{
    let mut indexed: Indexed16 = s
        .bytes()
        .enumerate()
        .collect();

    indexed.sort_by_key(|&(_, b)| key(b));

    let mut out: Digits16 = SmallVec::with_capacity(s.len());
    out.resize(s.len(), 0);

    for (rank, (original_idx, _)) in indexed.into_iter().enumerate() {
        out[original_idx] = if one_based_mod10 {
            ((rank + 1) % 10) as u8
        } else {
            rank as u8
        };
    }

    out.into_vec()
}

/// Converts a given string slice into a vector of numeric byte values.
///
/// # Arguments
///
/// * `s` - A string slice (`&str`) that will be converted into a vector of numeric byte values.
///
/// # Returns
///
/// A `Vec<u8>` containing numeric byte representations of the characters in the input string.
///
/// # Example
///
/// ```
/// let result = to_numeric("hello");
/// // `result` might depend on the implementation of `numeric_by_key`
/// ```
///
/// # Notes
///
/// This function is a wrapper around the `numeric_by_key` function, passing the input string,
/// a closure that directly maps its bytes, and a `false` boolean flag. Refer to the
/// `numeric_by_key` function for more details on the behavior and use.
///
pub fn to_numeric(s: &str) -> Vec<u8> {
    numeric_by_key(s, |b| b, false)
}

/// Converts a string to a `Vec<u8>` representing numeric values based on specific mappings.
///
/// # Description
/// This function takes a string slice as input and processes each byte of the string
/// using a transformation defined in the closure. It maps characters in the following way:
///
/// - Characters `'1'` through `'9'` are converted to their respective numeric values (1 to 9).
/// - The character `'0'` is mapped to the value `10`.
/// - All other characters are left unchanged.
///
/// The function internally uses `numeric_by_key` to apply the transformation and returns the resulting vector.
///
/// # Arguments
/// * `s` - A string slice (`&str`) to be processed.
///
/// # Returns
/// A `Vec<u8>` where each element represents a transformed numeric value or an unchanged byte based on the input string.
///
/// # Examples
/// ```
/// let input = "123045";
/// let result = to_numeric_one(input);
/// assert_eq!(result, vec![1, 2, 3, 10, 4, 5]);
/// ```
///
/// # Notes
/// - The input string cannot contain characters that are invalid UTF-8, as it processes it as Rust's `&str`.
/// - The `numeric_by_key` function used must provide the logic for applying the closure to the input string
///   and process it accordingly.
///
/// # Panics
/// This function will not panic as long as `numeric_by_key` handles all input cases appropriately.
///
pub fn to_numeric_one(s: &str) -> Vec<u8> {
    numeric_by_key(
        s,
        |b| match b {
            b'1'..=b'9' => b - b'0',
            b'0' => 10,
            _ => b,
        },
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    #[case("ARABESQUE", vec![0, 6, 1, 2, 3, 7, 5, 8, 4])]
    #[case("PJRJJJJJJS", vec![7, 0, 8, 1, 2, 3, 4, 5, 6, 9])]
    #[case("AAABRAACADAABRA", vec![0, 1, 2, 9, 13, 3, 4, 11, 5, 12, 6, 7, 10, 14, 8])]
    #[case("8238965327", vec![7, 0, 2, 8, 9, 5, 4, 3, 1, 6])]
    #[case("1234567890", vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0])]
    #[case("5051328370", vec![6, 0, 7, 2, 4, 3, 9, 5, 8, 1])]
    fn test_to_numeric(#[case] key: &str, #[case] expected: Vec<u8>) {
        assert_eq!(to_numeric(key), expected);
    }

    #[rstest]
    #[case("90210", vec![3, 4, 2, 1, 5])]
    #[case("OCTOPUS", vec![2, 1, 6, 3, 4, 7, 5])]
    #[case("IDREAMOFJE", vec![6, 2, 0, 3, 1, 8, 9, 5, 7, 4])]
    #[case("ANNIEWITHT", vec![1, 6, 7, 4, 2, 0, 5, 8, 3, 9])]
    #[case("TWASTHENIG", vec![8, 0, 1, 7, 9, 4, 2, 6, 5, 3])]
    #[case("HTBEFORECH", vec![6, 0, 1 ,3, 5, 8, 9, 4, 2, 7])]
    #[case("ARABESQUE",  vec![1, 7, 2, 3, 4, 8, 6, 9, 5])]
    #[case("PJRJJJJJJS", vec![8, 1, 9, 2, 3, 4, 5, 6, 7, 0])]
    #[case("3288628787", vec![3 ,1 ,7, 8, 4, 2, 9, 5, 0, 6])]
    #[case("8238965327", vec![8, 1, 3, 9, 0, 6, 5, 4, 2, 7])]
    #[case("5051328370", vec![5, 9, 6, 1, 3, 2, 8, 4, 7, 0])]
    fn test_to_numeric_one(#[case] s: &str, #[case] r: Vec<u8>) {
        assert_eq!(to_numeric_one(s), r);
    }
}


