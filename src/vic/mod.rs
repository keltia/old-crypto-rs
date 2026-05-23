//! VIC cipher implementation.
//!
//! The VIC cipher is a sophisticated pencil-and-paper cipher used by Soviet spy Reino Häyhänen
//! in the 1950s. It combines a straddling checkerboard with two transposition steps.
//!
//! Full description & test vectors: <http://www.quadibloc.com/crypto/pp1324.htm>
//! Additional information in [Kahn on Codes, 1984](https://www.goodreads.com/book/show/457215.Kahn_on_Codes)
//! ISBN: 978-0-02-560640-1
//!
use crate::Block;
use crate::helpers::{addmod10, to_numeric_one, Alphabet, Derive, Frequent};
use crate::transposition::{IrregularTransposition, Transposition};
use crate::vic::straddling::VicStraddling;
use crate::vic::subr::{
    chainadd, expand5to10, first_encode,
    rebuild_plaintext, split_plaintext, str2int, submod10,
};

use eyre::Result;

pub(crate) mod straddling;
pub(crate) mod subr;

/// VIC cipher implementation combining straddling checkerboard and transposition ciphers.
///
/// The VIC cipher uses a complex key derivation system and three main components:
/// - A straddling checkerboard for initial encoding
/// - A first regular transposition
/// - A second irregular transposition
///
#[derive(Debug)]
pub struct VicCipher<A: Alphabet, D: Derive<F>, F: Frequent> {
    // First transposition
    regular: Transposition,
    // Second transposition
    disrupted: IrregularTransposition,
    // Straddling Checkerboard
    sc: VicStraddling<A, D, F>,
}

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

impl<A: Alphabet, D: Derive<F>, F: Frequent> VicCipher<A, D, F> {
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
    ///     "77651"
    ///     "IDREAMOFJEANNIEWITHT",
    ///     "741776",
    ///     "6",
    /// ).unwrap();
    /// ```
    ///
    pub fn new(ind: &str, phrase: &str, imsg: &str, persn: usize) -> Result<Self> {
        // Line-A
        let line_a = str2int(imsg);
        // Line-B
        let line_b = str2int(&ind[..5]);

        let expanded = expand_key(phrase, &line_a, &line_b, persn)?;


        // Create the straddling checkerboard with Line-S
        //
        let sckey = expanded.sckey.iter().map(|&b| (b + b'0') as char).collect::<String>();
        let sc = VicStraddling::<A, D, F>::new(&sckey)?;

        // Transform our keys into strings for the rest.
        //
        let regular_str = expanded.second
            .iter()
            .map(|&b| (b + b'0') as char)
            .collect::<String>();

        let disrupted_str = expanded.third
            .iter()
            .map(|&b| (b + b'0') as char)
            .collect::<String>();

        // First transposition is regular, using 'second' as key
        //
        let first_tp = Transposition::new(&regular_str)?;

        // Second transposition is irregular, using 'third' as key
        //
        let second_tp = IrregularTransposition::new(&disrupted_str)?;

        Ok(VicCipher {
            regular: first_tp,
            disrupted: second_tp,
            sc,
        })
    }
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
pub(crate) fn expand_key(line_d: &str, line_b: &[u8], line_a: &[u8], persn: usize) -> Result<ExpandedKey> {
    // phrase = Line-D

    // Step 1. Line-C = Line-A - Line-B[:5] (mod 10)
    //
    let line_c = submod10(line_a, &line_b[..5]);

    // Step 2: Chain addition to 10 digits
    // Line-C = 6 9 5 9 2
    // 5 4 4 1 7 (6+9=(1)5, 9+5=(1)4, 9+5=(1)4, 9+1=(1)1, 5+2=7)
    // Line-F.1 = 6 9 5 9 2 5 4 4 1 7
    //
    let line_f1 = expand5to10(&line_c);

    // Step 3: Add to PH1
    //
    let line_e1 = to_numeric_one(&line_d[..10]);
    let line_e2 = to_numeric_one(&line_d[10..]);
    let line_g = addmod10(&line_e1, &line_f1);
    let line_h = first_encode(&line_g, &line_e2);

    let line_hs = line_h
        .iter()
        .map(|&b| (b + b'0') as char)
        .collect::<String>();

    // Line-H:
    // Line-J: sequencing of Line-H
    //
    let line_j = to_numeric_one(&line_hs);

    // Step 5: Chain addition 5 times
    //
    // Line-K
    // Line-L
    // Line-M
    // Line-N
    // Line-P
    //
    let mut line_p = line_h.clone();
    let mut raw_digits: Vec<u8> = vec![];
    for _ in 0..5 {
        let inter = chainadd(&line_p);
        raw_digits.extend(&inter);
        line_p = inter;
    }

    // Now that we have all the digits, we need to transpose them using line_j as the key.
    //
    let intermed = Transposition::new(&String::from_utf8(line_j)?)?;
    let mut all_digits = vec![0; raw_digits.len()];
    let n = intermed.encrypt(&mut all_digits, &raw_digits);
    assert_eq!(n, raw_digits.len());

    // Find two different values inside Line-P starting at the end, and use them to calculate
    // the size of the regular and disrupted keys.
    //
    let size_disrupted = persn + line_p[9] as usize;
    let mut idx = 8;
    while line_p[idx] == line_p[9] {
        idx -= 1;
    }
    let size_regular = persn + line_p[idx] as usize;

    // These digits are used for the second transposition key
    // And their numerical order for SC key.
    //
    let regular_key = &all_digits[..size_regular];
    let disrupted_key = &all_digits[size_regular..(size_regular + size_disrupted)];

    // Line-P: is the raww SC key
    // Line-S: sequenced
    //
    let line_ps = line_p
        .iter()
        .map(|&b| (b + b'0') as char)
        .collect::<String>();

    // Final SC key is the sequencing of Line-P
    // aka Line-S
    //
    let line_s = to_numeric_one(&line_ps);

    Ok(ExpandedKey {
        second: regular_key.to_vec(),
        third: disrupted_key.to_vec(),
        sckey: line_s,
    })
}


impl<A: Alphabet, D: Derive<F>, F: Frequent> Block for VicCipher<A, D, F> {
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
        //
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
        let tp1_len = self.regular.encrypt(&mut buf_tp1, &buf_sc[..sc_len]);

        self.disrupted.encrypt(dst, &buf_tp1[..tp1_len])
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
        //
        let mut buf_tp2 = vec![0u8; src.len()];
        let tp2_len = self.disrupted.decrypt(&mut buf_tp2, src);

        let mut buf_tp1 = vec![0u8; tp2_len];
        let tp1_len = self.regular.decrypt(&mut buf_tp1, &buf_tp2[..tp2_len]);

        let mut buf_sc = vec![0u8; tp1_len];
        let sc_len = self.sc.decrypt(&mut buf_sc, &buf_tp1[..tp1_len]);
        let sc_plain = &buf_sc[..sc_len];

        let res = rebuild_plaintext(sc_plain);
        assert_eq!(res.len(), sc_len - 1);
        assert_eq!(res.len(), dst.len());
        dst.copy_from_slice(res.as_slice());
        res.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::{Horizontal, LatinSC, VicEnglish, to_numeric_one};
    use crate::vic::VicStraddling;
    use crate::vic::subr::{chainadd, expand5to10, first_encode, submod10};

    type TestVic = VicCipher<LatinSC, Horizontal, VicEnglish>;

    #[test]
    fn test_new_cipher() {
        let c = TestVic::new("741776", "IDREAMOFJEANNIEWITHT", "77651", 6);
        assert!(c.is_ok());
    }

    #[test]
    fn test_vic_cipher_full() {
        let c = TestVic::new("741776", "IDREAMOFJEANNIEWITHT", "77651", 6).unwrap();

        let pt = "HELLOWORLD";
        let mut ct = vec![0u8; 100];
        let ct_actual_len = c.encrypt(&mut ct, pt.as_bytes());

        let ct_trimmed = &ct[..ct_actual_len];

        // Last digit of ind "741776" is 6.
        // imsg is "77651".
        // ct_trimmed should have imsg inserted at index 6.
        //
        assert!(ct_trimmed.len() >= 11);

        let mut decrypted = vec![0u8; 10];
        let dec_len = c.decrypt(&mut decrypted, ct_trimmed);

        let res = String::from_utf8_lossy(&decrypted[..dec_len]).to_string();
        assert_eq!(res, pt);
    }

    #[test]
    fn test_vic_wikipedia_example() {
        // From Wikipedia:
        // Phrase: TWASTHENIGHTBEFORECH
        // Date: 13 Sept 1959 -> 139195(9) (7 digits)
        // Personal Number: 6
        // Indicator: 72401 (first 5 digits)

        // Let's see how Wikipedia maps this to our New arguments.
        // persn: "6" (Personal number 6, usually represented as 2 digits for SC)
        // ind: "72401"
        // phrase: "TWASTHENIGHTBEFORECH"
        // imsg: "1391959"

        // Step 1: Subtraction modulo 10
        // Line-A = 7 2 4 0 1 (ikey5)
        // Line-B = 1 3 9 1 9 (first 5 of imsg)
        // Line-C = 6 9 5 9 2 (Line-A - Line-B mod 10)
        //
        let persn = 6;
        let line_b = str2int("1391959");
        let line_a = str2int("72401");
        let line_c = submod10(&line_a, &line_b[..5]);
        assert_eq!(line_c, vec![6, 9, 5, 9, 2]);

        // Step 2: Chain addition to 10 digits
        // Line-C = 6 9 5 9 2
        // 5 4 4 1 7 (6+9=(1)5, 9+5=(1)4, 9+5=(1)4, 9+1=(1)1, 5+2=7)
        // Line-F.1 = 6 9 5 9 2 5 4 4 1 7
        //
        let line_f1 = expand5to10(&line_c);
        assert_eq!(line_f1, vec![6, 9, 5, 9, 2, 5, 4, 4, 1, 7]);

        // Step 3: Add to PH1
        // Line-D: T W A S T H E N I G | H T B E F O R E C H
        // Line-E: 8 0 1 7 9 4 2 6 5 3 | 6 0 1 3 5 8 9 4 2 7
        let line_e1 = to_numeric_one("TWASTHENIG");
        assert_eq!(line_e1, vec![8, 0, 1, 7, 9, 4, 2, 6, 5, 3]);

        let line_e2 = to_numeric_one("HTBEFORECH");
        assert_eq!(line_e2, vec![6, 0, 1, 3, 5, 8, 9, 4, 2, 7]);

        // Line-E.1: 8 0 1 7 9 4 2 6 5 3
        // Line-F.1: 6 9 5 9 2 5 4 4 1 7 (expand5to10)
        // Line-G:   4 9 6 6 1 9 6 0 6 0
        let line_g = addmod10(&line_e1, &line_f1);
        assert_eq!(line_g, vec![4, 9, 6, 6, 1, 9, 6, 0, 6, 0]);

        // Line-G:   4 9 6 6 1 9 6 0 6 0
        // Line-F.2: 1 2 3 4 5 6 7 8 9 0
        // Line-E.2: 6 0 1 3 5 8 9 4 2 7
        let line_h = first_encode(&line_g, &line_e2);
        assert_eq!(line_h, vec![3, 2, 8, 8, 6, 2, 8, 7, 8, 7]);

        // Line-H:   3 2 8 8 6 2 8 7 8 7
        // Line-J:   3 1 7 8 4 2 9 5 0 6    (to_numeric_one)
        let line_hs = line_h
            .iter()
            .map(|&b| (b + b'0') as char)
            .collect::<String>();
        let line_j = to_numeric_one(&line_hs);
        assert_eq!(line_j, vec![3, 1, 7, 8, 4, 2, 9, 5, 0, 6]);

        // Step 5: Chain addition 5 times
        //
        let mut line_p = line_h.clone();
        let mut raw_digits: Vec<u8> = vec![];
        for _ in 0..5 {
            let inter = chainadd(&line_p);
            raw_digits.extend(&inter);
            line_p = inter;
        }
        let raw_digits_str = raw_digits
            .iter()
            .map(|b| (*b + b'0') as char)
            .collect::<String>();
        assert_eq!(
            raw_digits_str,
            "50648055525602850077162035074878238571255051328370"
        );

        // Now that we have all the digits, we need to transpose them using line_j as the key.
        //
        let intermed = Transposition::new(&String::from_utf8(line_j).unwrap()).unwrap();
        let mut all_digits = vec![0; raw_digits.len()];
        let n = intermed.encrypt(&mut all_digits, &raw_digits);
        assert_eq!(n, raw_digits.len());

        // Line-H: 3 2 8 8 6 2 8 7 8 7
        // Line-J: 3 1 7 8 4 2 9 5 0 6
        //
        // Line-K: 5 0 6 4 8 0 5 5 5 2
        // Line-L: 5 6 0 2 8 5 0 0 7 7
        // Line-M: 1 6 2 0 3 5 0 7 4 8
        // Line-N: 7 8 2 3 8 5 7 1 2 5
        // Line-P: 5 0 5 1 3 2 8 3 7 0
        //
        assert_eq!(line_p, vec![5, 0, 5, 1, 3, 2, 8, 3, 7, 0]);

        // Find two different values inside Line-P starting at the end, and use them to calculate
        // the size of the regular and disrupted keys.
        //
        let size_disrupted = persn + line_p[9] as usize;
        let mut idx = 8;
        while line_p[idx] == line_p[9] {
            idx -= 1;
        }
        let size_regular = persn + line_p[idx] as usize;
        assert_eq!(size_regular, 13);
        assert_eq!(size_disrupted, 6);
        assert_eq!(all_digits[..13], vec![0, 6, 6, 8, 0, 0, 5, 5, 5, 2, 5, 5, 1]);
        assert_eq!(all_digits[13..19], vec![7, 5, 8, 8, 3, 8]);


        // These digits are used for the second transposition key
        // And their numerical order for SC key.
        //
        let regular_key = &all_digits[..size_regular];
        let disrupted_key = &all_digits[size_regular..(size_regular + size_disrupted)];

        assert_eq!(regular_key, vec![5, 0, 6, 4, 8, 0, 5, 5, 5, 2, 5, 6, 0]);
        assert_eq!(disrupted_key, vec![2, 8, 5, 0, 0, 7]);

        // Line-P: 5 0 5 1 3 2 8 3 7 0
        // Line-S: 5 9 6 1 3 2 8 4 7 0 (to_numeric_one)
        //
        let line_ps = line_p
            .iter()
            .map(|&b| (b + b'0') as char)
            .collect::<String>();
        assert_eq!(line_ps, "5051328370");

        // Final SC key is the sequencing of Line-P
        //
        let line_s = to_numeric_one(&line_ps);
        let line_ss = line_s
            .iter()
            .map(|&b| (b + b'0') as char)
            .collect::<String>();

        // This the key to the straddling checkerboard.
        //
        assert_eq!(line_s, vec![5, 9, 6, 1, 3, 2, 8, 4, 7, 0]);

        // Create the straddling checkerboard with Line-S
        //
        let sc = VicStraddling::<LatinSC, Horizontal, VicEnglish>::new(&line_ss);
        assert!(sc.is_ok());
        let sc = sc.unwrap();
        dbg!(&sc);

        // Transform our keys into strings for the rest.
        //
        let regular_str = regular_key
            .iter()
            .map(|&b| (b + b'0') as char)
            .collect::<String>();

        let disrupted_str = disrupted_key
            .iter()
            .map(|&b| (b + b'0') as char)
            .collect::<String>();

        // First transposition is regular, using 'second' as key
        //
        let first_tp = Transposition::new(&regular_str);
        assert!(first_tp.is_ok());

        // Second transposition is irregular, using 'third' as key
        //
        let second_tp = IrregularTransposition::new(&disrupted_str);
        assert!(second_tp.is_ok());

        let pt = "MEAN0500.NOT0915LIKEYOUDIDLASTTIME./ATTACKATDAWN.BYDAWNI";
        let mut ct = vec![0u8; pt.len() * 2];
        let _n = sc.encrypt(&mut ct, pt.as_bytes());

        let expected = "60253 80000 55500 00008 08731 98000 09991 11555 80677 64288 18666 76667 54997 60287 59956 96459 66583 38765 88665 8337";
        assert_eq!(ct, expected.as_bytes());
    }

    #[test]
    fn test_split_plaintext_invariants() {
        let pt = b"ABCDEFGHIJKLMNOP";
        let ml = 6;
        let out = split_plaintext(pt, ml);
        assert_eq!(out.len(), pt.len() + 1);

        let dash_positions: Vec<usize> = out
            .iter()
            .enumerate()
            .filter_map(|(i, &b)| if b == b'-' { Some(i) } else { None })
            .collect();
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
