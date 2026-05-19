use crate::helpers::to_numeric;

/// Intermediate structure holding expanded key material.
///
/// This structure contains the derived keys used for the two transpositions
/// and the straddling checkerboard.
///
#[derive(Debug)]
pub(crate) struct ExpandedKey {
    /// Key for the first (regular) transposition
    pub(crate) second: Vec<u8>,
    /// Key for the second (irregular) transposition
    pub(crate) third: Vec<u8>,
    /// Key for the straddling checkerboard
    pub(crate) sckey: Vec<u8>,
}

/// Expands the key material into the three keys needed for the VIC cipher.
///
/// This function performs the complex key derivation process using chain addition
/// and modular arithmetic to generate the transposition and checkerboard keys.
///
/// # Arguments
///
/// * `phrase` - Key phrase (at least 20 characters) split into two parts
/// * `imsg` - Initial message number as byte array
/// * `ikey5` - First 5 digits of indicator as byte array
///
/// # Returns
///
/// Returns an `ExpandedKey` structure containing all derived key material.
///
pub(crate) fn expand_key(phrase: &str, line_b: &[u8], line_a: &[u8]) -> ExpandedKey {
    // ikey5 = Line-A
    // imsg = Line-B
    // phrase = Line-D
    // ph1 = Line-E.1
    let line_e1: Vec<u8> = to_numeric_one(&phrase[..10]);
    // ph2 = Line-E.2
    let line_e2: Vec<u8> = to_numeric_one(&phrase[10..20]);

    // Line-C
    let mut line_c = submod10(line_b, line_a);
    // Line-F.1
    line_c = chainadd_extend(&line_c, 5);

    // Line-G =  Line-E1 + Line-F.1
    addmod10_inplace(&mut line_c, &line_e1);
    // Line-H: encode Line-G with Line-E.2
    let line_h = first_encode(&line_c, &line_e2);
    let line_hs = line_h.iter().map(|&b| (b + b'0') as char).collect::<String>();
    dbg!(&line_hs);
    // Line-J
    let second = to_numeric_one(&line_hs);
    dbg!(&second.iter().map(|&b| (b + b'0') as char).collect::<String>());

    let mut r = second.clone();
    for _ in 0..5 {
        chainadd_inplace(&mut r);
    }
    dbg!(&r);
    // In VIC, the key for the second transposition and the SC is derived
    // from the 5th iteration of chain addition.
    let third = r.clone();
    let r_str: String = r.iter().map(|&b| (b + b'0') as char).collect();
    let sckey = to_numeric(&r_str);

    ExpandedKey {
        second,
        third,
        sckey,
    }
}


/// Converts a string of digits to a vector of integers.
///
/// # Arguments
///
/// * `str` - String containing ASCII digits ('0'-'9')
///
/// # Returns
///
/// Returns a vector of bytes where each byte is the numeric value (0-9) of the digit.
///
#[inline]
pub(crate) fn str2int(str: &str) -> Vec<u8> {
    str.bytes().map(|b| b - b'0').collect()
}

/// Adds two vectors element-wise modulo 10 in-place.
///
/// Each element in `a` is replaced with `(a[i] + b[i]) % 10`. The operation
/// stops when either vector is exhausted.
///
/// # Arguments
///
/// * `a` - Mutable slice that will be modified with the result
/// * `b` - Slice to add to `a`
///
#[inline]
pub(crate) fn addmod10_inplace(a: &mut [u8], b: &[u8]) {
    for (x, y) in a.iter_mut().zip(b) {
        *x = (*x + *y) % 10;
    }
}

#[inline]
pub(crate) fn submod10(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| (x + 10 - y) % 10).collect()
}

/// Performs chain addition in-place on a vector.
///
/// Chain addition adds each element to its right neighbor (wrapping around at the end)
/// and stores the result modulo 10 in the original position.
///
/// # Arguments
///
/// * `a` - Mutable slice to perform chain addition on
///
pub(crate) fn chainadd_inplace(a: &mut [u8]) {
    let l = a.len();
    if l < 2 { return; }
    for i in 0..l - 1 {
        a[i] = (a[i] + a[i + 1]) % 10;
    }
    let first = a[0];
    a[l - 1] = (a[l - 1] + first) % 10;
}

/// Performs chain addition on a vector, and returns the result.
///
/// Chain addition adds each element to its right neighbor (wrapping around at the end)
/// and stores the result modulo 10 in the original position.
///
/// # Arguments
///
/// * `a` - Slice to perform chain addition on
///
pub(crate) fn chainadd(a: &[u8]) -> Vec<u8> {
    let l = a.len();
    let mut r = Vec::with_capacity(l);

    if l < 2 { return vec![]; }
    for i in 0..l - 1 {
        r.push((a[i] + a[i + 1]) % 10);
    }
    r.push((a[l - 1] + r[0]) % 10);
    r.to_vec()
}

/// Extends a vector using chain addition.
///
/// Each new element is the sum of the element at current index and its successor.
///
/// # Arguments
///
/// * `a` - Initial slice
/// * `n` - Number of elements to add
///
pub(crate) fn chainadd_extend(a: &[u8], n: usize) -> Vec<u8> {
    let mut res = Vec::with_capacity(a.len() + n);
    res.extend_from_slice(a);
    for i in 0..n {
        let sum = (res[i] + res[i+1]) % 10;
        res.push(sum);
    }
    res
}

/// In the original VIC cipher, in order to confuse the adversary even more, plaintext is cut
/// around the middle, and the two parts are swapped with a marker in between.
///
/// (cf. Kahn on Codes)
///
//     let ml = pt.len() / 2;
//     let intv = rand::rng().random_range(1..=(ml / 2));
//     let ml = ml - intv;
/// Example:
/// "ABCDEFGH" is split around the middle and becomes "EFGH-ABCD".
///
pub(crate) fn split_plaintext(pt: &[u8], ml: usize) -> Vec<u8> {
    let mut beg = pt[0..ml].to_vec();
    let mut res = pt[ml..].to_vec();
    res.append(&mut vec![b'-' as u8]);
    res.append(&mut beg);
    res
}

pub(crate) fn rebuild_plaintext(pt: &[u8]) -> Vec<u8> {
    let idx = pt.split(|&c| c == b'-').collect::<Vec<&[u8]>>();
    let mut res = idx[1].to_vec();
    res.append(&mut idx[0].to_vec());
    res
}

/// Expands a 5-element vector to 10 elements using chain addition.
///
/// The result contains the original 5 elements followed by 5 elements
/// generated by chain addition.
///
/// # Arguments
///
/// * `a` - Input slice (typically 5 elements)
///
/// # Returns
///
/// Returns a 10-element vector.
///
#[inline]
#[cfg(test)]
pub(crate) fn expand5to10(a: &[u8]) -> Vec<u8> {
    chainadd_extend(a, 5)
}

/// Encodes vector `a` using vector `b` as a lookup table.
///
/// Each element in `a` is used as an index (after adjustment) into vector `b`.
///
/// # Arguments
///
/// * `a` - Vector of indices
/// * `b` - Lookup table vector
///
/// # Returns
///
/// Returns a vector where each element is `b[((a[i] + 10) % 10) - 1]`.
///
#[inline]
pub(crate) fn first_encode(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().map(|&v| b[((v as i32 + 9) % 10) as usize]).collect()
}

/// This is `to_numeric`, but 1-based for digits:
/// '1' ranks first, ..., '9' ranks ninth, and '0' ranks tenth.
///
/// Duplicate digits are ranked left-to-right because `sort_by_key` is stable.
///
pub(crate) fn to_numeric_one(s: &str) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use crate::helpers::{to_numeric, EnglishExt, Horizontal, LatinSC};
    use crate::vic::subr::{addmod10_inplace, submod10};
    use crate::VicCipher;

    type OurVic = VicCipher::<LatinSC, Horizontal, EnglishExt>;

    #[test]
    fn test_new_cipher() {
        let c = OurVic::new("741776", "IDREAMOFJEANNIEWITHT", "77651");
        assert!(c.is_ok());
    }

    #[rstest]
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

    #[rstest]
    #[case(vec![8, 6, 1, 5, 4], vec![2, 0, 9, 5, 2], vec![0, 6, 0, 0, 6])]
    #[case(vec![7, 7, 6, 5, 1], vec![7, 4, 1, 7, 7], vec![4, 1, 7, 2, 8])]
    fn test_addmod10(#[case] mut a: Vec<u8>, #[case] b: Vec<u8>, #[case] c: Vec<u8>) {
        addmod10_inplace(&mut a, &b);
        assert_eq!(a, c);
    }

    #[rstest]
    #[case(vec![8, 6, 1, 5, 4], vec![2, 0, 9, 5, 2], vec![6, 6, 2, 0, 2])]
    #[case(vec![7, 7, 6, 5, 1], vec![7, 4, 1, 7, 7], vec![0, 3, 5, 8, 4])]
    fn test_submod10(#[case] a: Vec<u8>, #[case] b: Vec<u8>, #[case] c: Vec<u8>) {
        assert_eq!(submod10(&a, &b), c);
    }

    #[rstest]
    #[case(vec![8, 6, 1, 5, 4], vec![4, 7, 6, 9, 8])]
    #[case(vec![7, 7, 6, 5, 1], vec![4, 3, 1, 6, 5])]
    #[case(vec![3, 2, 8, 8, 6, 2, 8, 7, 8, 7], vec![5, 0, 6, 4, 8, 0, 5, 5, 5, 2])]
    #[case(vec![5, 0, 6, 4, 8, 0, 5, 5, 5, 2], vec![5, 6, 0, 2, 8, 5, 0, 0, 7, 7])]
    fn test_chainadd_inplace(#[case] mut a: Vec<u8>, #[case] b: Vec<u8>) {
        chainadd_inplace(&mut a);
        assert_eq!(a, b);
    }

    #[rstest]
    #[case(vec![8, 6, 1, 5, 4], vec![4, 7, 6, 9, 8])]
    #[case(vec![7, 7, 6, 5, 1], vec![4, 3, 1, 6, 5])]
    #[case(vec![3, 2, 8, 8, 6, 2, 8, 7, 8, 7], vec![5, 0, 6, 4, 8, 0, 5, 5, 5, 2])]
    #[case(vec![5, 0, 6, 4, 8, 0, 5, 5, 5, 2], vec![5, 6, 0, 2, 8, 5, 0, 0, 7, 7])]
    fn test_chainadd(#[case] mut a: Vec<u8>, #[case] b: Vec<u8>) {
        let r = chainadd(&a);
        assert_eq!(r, b);
    }

    #[rstest]
    #[case(vec![8, 6, 1, 5, 4], vec![8, 6, 1, 5, 4, 4, 7, 6, 9, 8])]
    #[case(vec![7, 7, 6, 5, 1], vec![7, 7, 6, 5, 1, 4, 3, 1, 6, 5])]
    #[case(vec![0, 3, 5, 8, 4], vec![0, 3, 5, 8, 4, 3, 8, 3, 2, 7])]
    fn test_expand5to10(#[case] a: Vec<u8>, #[case] b: Vec<u8>) {
        assert_eq!(expand5to10(&a), b);
    }

    #[test]
    fn test_first_encode() {
        // Line--G
        let r1 = vec![6, 5, 5, 1, 5, 1, 7, 8, 9, 1];
        // Line-E.2
        let r2 = vec![1, 6, 7, 4, 2, 0, 5, 8, 3, 9];
        // Line-H
        let r = vec![0, 2, 2, 1, 2, 1, 5, 8, 3, 1];
        assert_eq!(first_encode(&r1, &r2), r);
    }

    #[test]
    fn test_first_encode_wp() {
        // Line--G
        let r1 = vec![4, 9, 6, 6, 1, 9, 6, 0, 6, 0];
        // Line-E.2
        let r2 = vec![6, 0, 1, 3, 5, 8, 9, 4, 2, 7];
        // Line-H
        let r = vec![3, 2, 8, 8, 6, 2, 8, 7, 8, 7];
        assert_eq!(first_encode(&r1, &r2), r);
    }

    #[rstest]
    #[case(b"ABCDEFGH", 1, b"BCDEFGH-A")]
    #[case(b"ABCDEFGH", 4, b"EFGH-ABCD")]
    #[case(b"ABCDEFGH", 7, b"H-ABCDEFG")]
    fn test_split_plaintext_cases(#[case] pt: &[u8], #[case] ml: usize, #[case] expected: &[u8]) {
        let out = split_plaintext(pt, ml);
        assert_eq!(out, expected);
    }

    #[rstest]
    #[case(b"ABCDEFGH", b"BCDEFGH-A")]
    #[case(b"ABCDEFGH", b"EFGH-ABCD")]
    #[case(b"ABCDEFGH", b"H-ABCDEFG")]
    fn test_rebuild_plaintext_cases(#[case] expected: &[u8], #[case] pt: &[u8]) {
        let out = rebuild_plaintext(pt);
        assert_eq!(out, expected);
    }
}
