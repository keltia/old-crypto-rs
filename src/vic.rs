//! VIC cipher implementation.
//!
//! The VIC cipher is a sophisticated pencil-and-paper cipher used by Soviet spy Reino Häyhänen
//! in the 1950s. It combines a straddling checkerboard with two transposition steps.
//!
//! Full description & test vectors: <http://www.quadibloc.com/crypto/pp1324.htm>
//!
use crate::Block;
use crate::transposition::Transposition;
use crate::straddling::{StraddlingCheckerboard, ALPHABET_TXT};
use crate::helpers;

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
    secondtp: Transposition,
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
    /// # use old_crypto_rs::vic::VicCipher;
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
        let secondtp = Transposition::new(&String::from_utf8_lossy(&expanded.third))?;

        // Straddling Checkerboard using 'sckey' (converted to letters) and 'persn'
        let sc_key_str: String = expanded.sckey.iter().map(|&v| (b'0' + v) as char).collect();
        let sc = StraddlingCheckerboard::new_with_freq(&sc_key_str, persn, "ATONESIR", ALPHABET_TXT)?;

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
    let ph1: Vec<u8> = helpers::to_numeric(&phrase[..10]).into_iter().map(|x| (x + 1) % 10).collect();
    let ph2: Vec<u8> = helpers::to_numeric(&phrase[10..]).into_iter().map(|x| (x + 1) % 10).collect();

    let res = submod10(imsg, ikey5);
    let first = expand5to10(&res);

    let tmp = addmod10(&first, &ph1);
    let second = first_encode(&tmp, &ph2);

    let mut r = second.clone();
    for _ in 0..5 {
        chainadd_inplace(&mut r);
    }

    // In VIC, the key for the second transposition and the SC is derived 
    // from the 5th iteration of chain addition.
    let third = r.clone();
    let r_str: String = r.iter().map(|&b| (b + b'0') as char).collect();
    let sckey = helpers::to_numeric(&r_str);

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
fn str2int(str: &str) -> Vec<u8> {
    str.bytes().map(|b| b - b'0').collect()
}

/// Performs element-wise addition modulo 10 on two vectors.
///
/// # Arguments
///
/// * `a` - First vector of bytes
/// * `b` - Second vector of bytes (must be same length as `a`)
///
/// # Returns
///
/// Returns a vector where each element is `(a[i] + b[i]) % 10`.
///
fn addmod10(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| (x + y) % 10).collect()
}

/// Performs element-wise subtraction modulo 10 on two vectors.
///
/// # Arguments
///
/// * `a` - First vector of bytes
/// * `b` - Second vector of bytes (must be same length as `a`)
///
/// # Returns
///
/// Returns a vector where each element is `(a[i] + 10 - b[i]) % 10`.
///
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
    if l == 0 { return; }
    for i in 0..l {
        a[i] = (a[i] + a[(i + 1) % l]) % 10;
    }
}

/// Performs chain addition on a vector, returning a new vector.
///
/// This is a non-mutating version of `chainadd_inplace`.
///
/// # Arguments
///
/// * `a` - Slice to perform chain addition on
///
/// # Returns
///
/// Returns a new vector with chain addition applied.
///
fn chainadd(a: &[u8]) -> Vec<u8> {
    let mut b = a.to_vec();
    chainadd_inplace(&mut b);
    b
}

/// Expands a 5-element vector to 10 elements using chain addition.
///
/// The result contains the original 5 elements followed by the chain addition
/// of those 5 elements.
///
/// # Arguments
///
/// * `a` - Input slice (typically 5 elements)
///
/// # Returns
///
/// Returns a vector with the original elements followed by their chain addition.
///
fn expand5to10(a: &[u8]) -> Vec<u8> {
    let mut res = a.to_vec();
    res.extend_from_slice(&chainadd(a));
    res
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
fn first_encode(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().map(|&v| b[((v as i32 + 10) % 10 - 1) as usize]).collect()
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
        // 1. Straddling Checkerboard
        // 2. First Transposition (regular)
        // 3. Second Transposition (irregular)

        let mut buf_sc = vec![0u8; src.len() * 3]; // Straddling can expand
        let sc_len = self.sc.encrypt(&mut buf_sc, src);
        let sc_res = &buf_sc[..sc_len];

        let mut buf_tp1 = vec![0u8; sc_res.len()];
        let tp1_len = self.firsttp.encrypt(&mut buf_tp1, sc_res);

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

        let mut buf_tp2 = vec![0u8; src.len()];
        let tp2_len = self.secondtp.decrypt(&mut buf_tp2, src);

        let mut buf_tp1 = vec![0u8; tp2_len];
        let tp1_len = self.firsttp.decrypt(&mut buf_tp1, &buf_tp2[..tp2_len]);

        self.sc.decrypt(dst, &buf_tp1[..tp1_len])
    }
}

#[cfg(test)]
mod tests {
    use crate::helpers::output_as_block;
    use super::*;
    use rstest::rstest;

    #[test]
    fn test_new_cipher() {
        let _c = VicCipher::new("89", "741776", "IDREAMOFJEANNIEWITHT", "77651").unwrap();
    }

    #[rstest]
    #[case("IDREAMOFJE", vec![6, 2, 0, 3, 1, 8, 9, 5, 7, 4])]
    #[case("ANNIEWITHT", vec![1, 6, 7, 4, 2, 0, 5, 8, 3, 9])]
    fn test_to_numeric_one(#[case] s: &str, #[case] r: Vec<u8>) {
        let res: Vec<u8> = helpers::to_numeric(s).into_iter().map(|x| (x + 1) % 10).collect();
        assert_eq!(res, r);
    }

    #[rstest]
    #[case(vec![8, 6, 1, 5, 4], vec![2, 0, 9, 5, 2], vec![0, 6, 0, 0, 6])]
    #[case(vec![7, 7, 6, 5, 1], vec![7, 4, 1, 7, 7], vec![4, 1, 7, 2, 8])]
    fn test_addmod10(#[case] a: Vec<u8>, #[case] b: Vec<u8>, #[case] c: Vec<u8>) {
        assert_eq!(addmod10(&a, &b), c);
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
    fn test_chainadd(#[case] a: Vec<u8>, #[case] b: Vec<u8>) {
        assert_eq!(chainadd(&a), b);
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
        c.encrypt(&mut ct, pt.as_bytes());
        
        let ct_len = ct.iter().position(|&x| x == 0).unwrap_or(ct.len());
        let ct_trimmed = &ct[..ct_len];

        dbg!(ct_trimmed);

        let mut decrypted = vec![0u8; 100];
        c.decrypt(&mut decrypted, ct_trimmed);
        
        let res = String::from_utf8_lossy(&decrypted).trim_matches('\0').to_string();
        assert_eq!(res, pt);
    }

    #[test]
    fn test_vic_cipher_example() {
        let c = VicCipher::new("89", "741776", "IDREAMOFJEANNIEWITHT", "77651").unwrap();

        let pt = "WEAREPLEASEDTOHEAROFYOURSUCCESSINESTABLISHINGYOURFALSEIDENTITYYOUWILLBESENTSOMEMONEYTOCOVEREXPENSESWITHINAMONTH";
        let mut ct = vec![0u8; 200];
        c.encrypt(&mut ct, pt.as_bytes());

        let ct_len = ct.iter().position(|&x| x == 0).unwrap_or(ct.len());
        let ct_trimmed = &ct[..ct_len];

        println!("{:?}", output_as_block(&String::from_utf8_lossy(&ct_trimmed).to_string()));

        let mut decrypted = vec![0u8; 200];
        c.decrypt(&mut decrypted, ct_trimmed);

        let res = String::from_utf8_lossy(&decrypted).trim_matches('\0').to_string();
        assert_eq!(res, pt);
    }
}
