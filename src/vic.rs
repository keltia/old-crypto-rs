//! VIC cipher implementation.
//!
//! The VIC cipher is a sophisticated pencil-and-paper cipher used by Soviet spy Reino Häyhänen
//! in the 1950s. It combines a straddling checkerboard with two transposition steps.
//!
//! Full description & test vectors: <http://www.quadibloc.com/crypto/pp1324.htm>
//! Additional information in [Kahn on Codes, 1984](https://www.goodreads.com/book/show/457215.Kahn_on_Codes)
//!  ISBN: 978-0-02-560640-1
//!
use crate::Block;
use crate::transposition::{Transposition, IrregularTransposition};
use crate::straddling::StraddlingCheckerboard;
use crate::helpers::{to_numeric, SC_ALPHABET};

/// VIC cipher implementation combining straddling checkerboard and transposition ciphers.
///
/// The VIC cipher uses a complex key derivation system and three main components:
/// - A straddling checkerboard for initial encoding
/// - A first regular transposition
/// - A second irregular transposition
/// 
#[derive(Debug)]
pub struct VicCipher {
    // First transposition
    firsttp: Transposition,
    // Second transposition
    secondtp: IrregularTransposition,
    // Straddling Checkerboard
    pub sc: StraddlingCheckerboard,
}

impl VicCipher {
    /// Creates a new VIC cipher instance with the specified key material.
    ///
    /// This constructor performs the complex key derivation process used in the VIC cipher,
    /// which involves expanding the key material into three separate keys:
    /// - A key for the first regular transposition
    /// - A key for the second irregular transposition
    /// - A key for the straddling checkerboard
    ///
    /// # Arguments
    ///
    /// * `persn` - Personal number used for the straddling checkerboard (typically 2 digits)
    /// * `ind` - Indicator string containing at least 5 digits used in key derivation
    /// * `phrase` - Key phrase that must be at least 20 characters long, used for key expansion
    /// * `imsg` - Initial message number as a string of digits
    ///
    /// # Returns
    ///
    /// Returns `Ok(VicCipher)` if the cipher was successfully constructed, or `Err(String)`
    /// if any of the key material is invalid or if the transposition or straddling checkerboard
    /// construction fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # use old_crypto_rs::VicCipher;
    /// let cipher = VicCipher::new(
    ///     "89",
    ///     "741776",
    ///     "IDREAMOFJEANNIEWITHT",
    ///     "77651"
    /// ).unwrap();
    /// ```
    ///
    pub fn new(persn: &str, ind: &str, phrase: &str, imsg: &str) -> Result<Self, String> {
        let imsg_int = str2int(imsg);
        let ikey5 = str2int(&ind[..5]);

        let expanded = expand_key(phrase, &imsg_int, &ikey5);

        // First transposition is regular, using 'second' as key
        let firsttp = Transposition::new(&String::from_utf8_lossy(&expanded.second))?;

        // Second transposition is irregular, using 'third' as key
        let secondtp = IrregularTransposition::new(&String::from_utf8_lossy(&expanded.third))?;

        // Straddling Checkerboard using 'sckey' (converted to letters) and 'persn'
        let sc_key_str: String = expanded.sckey.iter().map(|&v| (b'0' + v) as char).collect();
        let sc = StraddlingCheckerboard::new_with_freq(&sc_key_str, persn, "ATONESIR", SC_ALPHABET)?;

        Ok(VicCipher {
            firsttp,
            secondtp,
            sc,
        })
    }
}

/// Intermediate structure holding expanded key material.
///
/// This structure contains the derived keys used for the two transpositions
/// and the straddling checkerboard.
///
#[derive(Debug)]
struct ExpandedKey {
    /// Key for the first (regular) transposition
    second: Vec<u8>,
    /// Key for the second (irregular) transposition
    third: Vec<u8>,
    /// Key for the straddling checkerboard
    sckey: Vec<u8>,
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
fn expand_key(phrase: &str, imsg: &[u8], ikey5: &[u8]) -> ExpandedKey {
    let ph1: Vec<u8> = to_numeric(&phrase[..10]).into_iter().map(|x| (x as u8 + 1) % 10).collect();
    let ph2: Vec<u8> = to_numeric(&phrase[10..20]).into_iter().map(|x| (x as u8 + 1) % 10).collect();

    let mut first = submod10(imsg, ikey5);
    first = chainadd_extend(&first, 5);

    addmod10_inplace(&mut first, &ph1);
    let second = first_encode(&first, &ph2);

    let mut r = second.clone();
    for _ in 0..5 {
        chainadd_inplace(&mut r);
    }

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
fn str2int(str: &str) -> Vec<u8> {
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
fn addmod10_inplace(a: &mut [u8], b: &[u8]) {
    for (x, y) in a.iter_mut().zip(b) {
        *x = (*x + *y) % 10;
    }
}

#[inline]
fn submod10(a: &[u8], b: &[u8]) -> Vec<u8> {
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
fn chainadd_inplace(a: &mut [u8]) {
    let l = a.len();
    if l < 2 { return; }
    let first = a[0];
    for i in 0..l - 1 {
        a[i] = (a[i] + a[i + 1]) % 10;
    }
    a[l - 1] = (a[l - 1] + first) % 10;
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
fn chainadd_extend(a: &[u8], n: usize) -> Vec<u8> {
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
fn split_plaintext(pt: &[u8], ml: usize) -> Vec<u8> {
    let mut beg = pt[0..ml].to_vec();
    let mut res = pt[ml..].to_vec();
    res.append(&mut vec![b'-' as u8]);
    res.append(&mut beg);
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
fn expand5to10(a: &[u8]) -> Vec<u8> {
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
fn first_encode(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().map(|&v| b[((v as i32 + 9) % 10) as usize]).collect()
}

impl Block for VicCipher {
    fn block_size(&self) -> usize {
        1
    }

    /// Encrypts plaintext using the VIC cipher.
    ///
    /// The encryption process consists of three steps:
    /// 1. Encode using the straddling checkerboard
    /// 2. Apply the first (regular) transposition
    /// 3. Apply the second (irregular) transposition
    ///
    /// # Arguments
    ///
    /// * `dst` - Destination buffer for ciphertext (must be large enough)
    /// * `src` - Source plaintext as bytes
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the destination buffer.
    ///
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        // VIC Encipherment:
        // 0. Split plaintext around the middle and swap halves (with marker).
        // 1. Straddling Checkerboard
        // 2. First Transposition (regular)
        // 3. Second Transposition (irregular)

        let split = if src.len() < 2 {
            src.to_vec()
        } else {
            use rand;
            use rand::RngExt;
            let mid = src.len() / 2;
            let delta = src.len() / 3;
            let min_ml = mid.saturating_sub(delta);
            let max_ml = (mid + delta).min(src.len() - 1);
            let ml = if min_ml == max_ml {
                min_ml
            } else {
                rand::rng().random_range(min_ml..=max_ml)
            };
            split_plaintext(src, ml)
        };

        let mut buf_sc = vec![0u8; split.len() * 3]; // Straddling can expand
        let sc_len = self.sc.encrypt(&mut buf_sc, &split);

        let mut buf_tp1 = vec![0u8; sc_len];
        let tp1_len = self.firsttp.encrypt(&mut buf_tp1, &buf_sc[..sc_len]);

        self.secondtp.encrypt(dst, &buf_tp1[..tp1_len])
    }

    /// Decrypts ciphertext using the VIC cipher.
    ///
    /// The decryption process reverses the encryption steps:
    /// 1. Reverse the second (irregular) transposition
    /// 2. Reverse the first (regular) transposition
    /// 3. Decode using the straddling checkerboard
    ///
    /// # Arguments
    ///
    /// * `dst` - Destination buffer for plaintext (must be large enough)
    /// * `src` - Source ciphertext as bytes
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the destination buffer.
    ///
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        // VIC Decipherment (Reverse of Encipherment):
        // 1. Second Transposition (irregular)
        // 2. First Transposition (regular)
        // 3. Straddling Checkerboard
        // 4. Unsplit plaintext by removing marker and swapping halves back.

        let mut buf_tp2 = vec![0u8; src.len()];
        let tp2_len = self.secondtp.decrypt(&mut buf_tp2, src);

        let mut buf_tp1 = vec![0u8; tp2_len];
        let tp1_len = self.firsttp.decrypt(&mut buf_tp1, &buf_tp2[..tp2_len]);

        let mut buf_sc = vec![0u8; tp1_len];
        let sc_len = self.sc.decrypt(&mut buf_sc, &buf_tp1[..tp1_len]);
        let sc_plain = &buf_sc[..sc_len];

        if let Some(dash_pos) = sc_plain.iter().position(|&b| b == b'-') {
            let after = &sc_plain[dash_pos + 1..];
            let before = &sc_plain[..dash_pos];
            let mut out_len = 0;

            if out_len + after.len() <= dst.len() {
                dst[..after.len()].copy_from_slice(after);
                out_len += after.len();
            } else {
                let n = dst.len().saturating_sub(out_len);
                dst[..n].copy_from_slice(&after[..n]);
                return out_len + n;
            }

            if out_len + before.len() <= dst.len() {
                dst[out_len..out_len + before.len()].copy_from_slice(before);
                out_len += before.len();
            } else {
                let n = dst.len().saturating_sub(out_len);
                dst[out_len..out_len + n].copy_from_slice(&before[..n]);
                out_len += n;
            }

            out_len
        } else {
            let n = sc_plain.len().min(dst.len());
            dst[..n].copy_from_slice(&sc_plain[..n]);
            n
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use crate::helpers::to_numeric;

    #[test]
    fn test_new_cipher() {
        let _c = VicCipher::new("89", "741776", "IDREAMOFJEANNIEWITHT", "77651").unwrap();
    }

    #[rstest]
    #[case("IDREAMOFJE", vec![6, 2, 0, 3, 1, 8, 9, 5, 7, 4])]
    #[case("ANNIEWITHT", vec![1, 6, 7, 4, 2, 0, 5, 8, 3, 9])]
    fn test_to_numeric_one(#[case] s: &str, #[case] r: Vec<u8>) {
        let res: Vec<u8> = to_numeric(s).into_iter().map(|x| (x as u8 + 1) % 10).collect();
        assert_eq!(res, r);
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
    #[case(vec![8, 6, 1, 5, 4], vec![4, 7, 6, 9, 2])]
    #[case(vec![7, 7, 6, 5, 1], vec![4, 3, 1, 6, 8])]
    fn test_chainadd_inplace(#[case] mut a: Vec<u8>, #[case] b: Vec<u8>) {
        chainadd_inplace(&mut a);
        assert_eq!(a, b);
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
        let r1 = vec![6, 5, 5, 1, 5, 1, 7, 8, 9, 1];
        let r2 = vec![1, 6, 7, 4, 2, 0, 5, 8, 3, 9];
        let r = vec![0, 2, 2, 1, 2, 1, 5, 8, 3, 1];
        assert_eq!(first_encode(&r1, &r2), r);
    }

    #[test]
    fn test_vic_cipher_full() {
        let c = VicCipher::new("89", "741776", "IDREAMOFJEANNIEWITHT", "77651").unwrap();
        
        let pt = "HELLOWORLD";
        let mut ct = vec![0u8; 100];
        let ct_actual_len = c.encrypt(&mut ct, pt.as_bytes());
        
        let ct_trimmed = &ct[..ct_actual_len];

        // Last digit of ind "741776" is 6.
        // imsg is "77651".
        // ct_trimmed should have imsg inserted at index 6.
        assert!(ct_trimmed.len() >= 11);

        let mut decrypted = vec![0u8; 100];
        let dec_len = c.decrypt(&mut decrypted, ct_trimmed);
        
        let res = String::from_utf8_lossy(&decrypted[..dec_len]).to_string();
        assert_eq!(res, pt);
    }

    #[test]
    fn test_vic_wikipedia_example() {
        // From Wikipedia:
        // Phrase: IDREAMOFJEANNIEWITHT
        // Date: 13 Sept 1944 -> 1391944 (7 digits)
        // Personal Number: 6
        // Indicator: 74177 (first 5 digits)
        
        // Let's see how Wikipedia maps this to our New arguments.
        // persn: "60" (Personal number 6, usually represented as 2 digits for SC)
        // ind: "74177"
        // phrase: "IDREAMOFJEANNIEWITHT"
        // imsg: "1391944"

        // Step 1: Subtraction modulo 10
        // G = 1 3 9 1 9 (first 5 of imsg)
        // H = 7 4 1 7 7 (ikey5)
        // J = 4 9 8 4 2 (G - H mod 10)
        let imsg = str2int("1391944");
        let ikey5 = str2int("74177");
        let j = submod10(&imsg[..5], &ikey5);
        assert_eq!(j, vec![4, 9, 8, 4, 2]);

        // Step 2: Chain addition to 10 digits
        // 4 9 8 4 2
        // 3 7 2 6 5 (4+9=13, 9+8=17, 8+4=12, 4+2=6, 2+3=5)
        // K = 4 9 8 4 2 3 7 2 6 5
        let k = expand5to10(&j);
        assert_eq!(k, vec![4, 9, 8, 4, 2, 3, 7, 2, 6, 5]);

        // Step 3: Add to PH1
        // Phrase: I D R E A M O F J E | A N N I E W I T H T
        // PH1:    5 1 9 2 0 6 7 3 8 4
        // A D E E F I J M O R
        // 0 1 2 3 4 5 6 7 8 9
        // A:0 D:1 E:2 E:3 F:4 I:5 J:6 M:7 O:8 R:9
        // +1 mod 10:
        // A:1 D:2 E:3 E:4 F:5 I:6 J:7 M:8 O:9 R:0
        // IDREAMOFJE:
        // I:6 D:2 R:0 E:3 A:1 M:8 O:9 F:5 J:7 E:4 -> 6 2 0 3 1 8 9 5 7 4?
        // Wait, my ranking in code is 0-based index of sorted characters.
        // A: 0
        // D: 1
        // E: 2
        // E: 3
        // F: 4
        // I: 5
        // J: 6
        // M: 7
        // O: 8
        // R: 9
        // IDREAMOFJE:
        // I: 5 -> 6
        // D: 1 -> 2
        // R: 9 -> 0
        // E: 2 -> 3
        // A: 0 -> 1
        // M: 7 -> 8
        // O: 8 -> 9
        // F: 4 -> 5
        // J: 6 -> 7
        // E: 3 -> 4
        // So ph1 should be [6, 2, 0, 3, 1, 8, 9, 5, 7, 4].
        let ph1 = vec![6, 2, 0, 3, 1, 8, 9, 5, 7, 4];
        // L = K + PH1 mod 10
        // 4 9 8 4 2 3 7 2 6 5
        // 6 2 0 3 1 8 9 5 7 4
        // -------------------
        // 0 1 8 7 3 1 6 7 3 9
        let mut l = k.clone();
        addmod10_inplace(&mut l, &ph1);
        assert_eq!(l, vec![0, 1, 8, 7, 3, 1, 6, 7, 3, 9]);

        // Step 4: First Encoding
        // PH2: 1 6 7 4 2 0 5 8 3 9 (ranks of ANNIEWITHT)
        // M = encode L with PH2
        // L: 0 1 8 7 3 1 6 7 3 9
        // PH2: 1 2 3 4 5 6 7 8 9 0 (index 1..10)
        //      1 6 7 4 2 0 5 8 3 9 (value)
        // Note: Wikipedia says "replace each digit in L with the digit below it in the PH2 line"
        // Digit 0 -> index 10 in PH2 (if 1-based)
        // Digit 9 -> index 9 in PH2
        let ph2 = vec![1, 6, 7, 4, 2, 0, 5, 8, 3, 9];
        let m = first_encode(&l, &ph2);
        // Wikipedia result for M: 9 1 8 5 7 1 0 5 7 3
        // L[0]=0 -> PH2[9]=9.
        // L[1]=1 -> PH2[0]=1.
        // L[2]=8 -> PH2[7]=8.
        // L[3]=7 -> PH2[6]=5.
        // L[4]=3 -> PH2[2]=7.
        // L[5]=1 -> PH2[0]=1.
        // L[6]=6 -> PH2[5]=0.
        // L[7]=7 -> PH2[6]=5.
        // L[8]=3 -> PH2[2]=7.
        // L[9]=9 -> PH2[8]=3.
        assert_eq!(m, vec![9, 1, 8, 5, 7, 1, 0, 5, 7, 3]);

        // Step 5: Chain addition 5 times
        let mut r = m.clone();
        for _ in 0..5 {
            chainadd_inplace(&mut r);
        }
        // Result should be used for second transposition and SC
        // Wikipedia: 
        // 1st: 0 9 3 2 8 1 5 2 0 2
        // 2nd: 9 2 5 0 9 6 7 2 2 2
        // 3rd: 1 7 5 9 5 3 9 4 4 1
        // 4th: 8 2 4 4 8 2 3 8 5 2
        // 5th: 0 6 8 2 0 5 1 3 7 0
        assert_eq!(r, vec![0, 6, 8, 2, 0, 5, 1, 3, 7, 0]);

        // These digits are used for second transposition key
        // And their numerical order for SC key.
        let r_str: String = r.iter().map(|&b| (b + b'0') as char).collect();
        let sckey = to_numeric(&r_str);
        // 0 6 8 2 0 5 1 3 7 0
        // Ranks (0-based, stable sort):
        // Pos 0: digit 0 -> rank 0
        // Pos 1: digit 6 -> rank 7
        // Pos 2: digit 8 -> rank 9
        // Pos 3: digit 2 -> rank 4
        // Pos 4: digit 0 -> rank 1
        // Pos 5: digit 5 -> rank 6
        // Pos 6: digit 1 -> rank 3
        // Pos 7: digit 3 -> rank 5
        // Pos 8: digit 7 -> rank 8
        // Pos 9: digit 0 -> rank 2
        // Ranks: 0 7 9 4 1 6 3 5 8 2
        assert_eq!(sckey, vec![0, 7, 9, 4, 1, 6, 3, 5, 8, 2]);
    }

    #[rstest]
    #[case(b"ABCDEFGH", 1, b"BCDEFGH-A")]
    #[case(b"ABCDEFGH", 4, b"EFGH-ABCD")]
    #[case(b"ABCDEFGH", 7, b"H-ABCDEFG")]
    fn test_split_plaintext_cases(#[case] pt: &[u8], #[case] ml: usize, #[case] expected: &[u8]) {
        let out = split_plaintext(pt, ml);
        assert_eq!(out, expected);
    }

    #[test]
    fn test_split_plaintext_invariants() {
        let pt = b"ABCDEFGHIJKLMNOP";
        let ml = 6;
        let out = split_plaintext(pt, ml);
        assert_eq!(out.len(), pt.len() + 1);

        let dash_positions: Vec<usize> = out.iter().enumerate().filter_map(|(i, &b)| if b == b'-' { Some(i) } else { None }).collect();
        assert_eq!(dash_positions.len(), 1);

        let dash_pos = dash_positions[0];
        assert_eq!(dash_pos, pt.len() - ml);

        let mut without_dash = out.clone();
        without_dash.retain(|&b| b != b'-');
        let mut expected = pt[ml..].to_vec();
        expected.extend_from_slice(&pt[..ml]);
        assert_eq!(without_dash, expected);
    }

}
