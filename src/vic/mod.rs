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
use crate::helpers::{Alphabet, Derive, Frequent};
use crate::transposition::{IrregularTransposition, Transposition};
use crate::vic::straddling::VicStraddling;
use crate::vic::subr::{expand_key, rebuild_plaintext, split_plaintext, str2int};

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
    firsttp: Transposition,
    // Second transposition
    secondtp: IrregularTransposition,
    // Straddling Checkerboard
    pub sc: VicStraddling<A, D, F>,
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
    ///     "89",
    ///     "741776",
    ///     "IDREAMOFJEANNIEWITHT",
    ///     "77651"
    /// ).unwrap();
    /// ```
    ///
    pub fn new(ind: &str, phrase: &str, imsg: &str) -> Result<Self> {
        // Line-A
        let iv = str2int(imsg);
        // Line-B
        let ikey5 = str2int(&ind[..5]);

        let expanded = expand_key(phrase, &iv, &ikey5);

        // First transposition is regular, using 'second' as key
        //
        let firsttp = Transposition::new(&String::from_utf8_lossy(&expanded.second))?;

        // Second transposition is irregular, using 'third' as key
        //
        let secondtp = IrregularTransposition::new(&String::from_utf8_lossy(&expanded.third))?;

        // Straddling Checkerboard using 'sckey' (converted to letters) and 'persn'
        //
        let sc_key_str: String = expanded.sckey.iter().map(|&v| (b'0' + v) as char).collect();
        dbg!(&sc_key_str);
        let sc = VicStraddling::<A, D, F>::new(&sc_key_str)?;
        Ok(VicCipher {
            firsttp,
            secondtp,
            sc,
        })
    }
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
        //
        let mut buf_tp2 = vec![0u8; src.len()];
        let tp2_len = self.secondtp.decrypt(&mut buf_tp2, src);

        let mut buf_tp1 = vec![0u8; tp2_len];
        let tp1_len = self.firsttp.decrypt(&mut buf_tp1, &buf_tp2[..tp2_len]);

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
    use crate::helpers::{English, Horizontal, LatinSC, to_numeric};
    use crate::secom::addmod10;
    use crate::vic::subr::{chainadd, expand5to10, first_encode, submod10, to_numeric_one};

    type TestVic = VicCipher<LatinSC, Horizontal, English>;

    #[test]
    fn test_new_cipher() {
        let c = TestVic::new("741776", "IDREAMOFJEANNIEWITHT", "77651");
        assert!(c.is_ok());
    }

    #[test]
    fn test_vic_cipher_full() {
        let c = TestVic::new("741776", "IDREAMOFJEANNIEWITHT", "77651").unwrap();

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
        let line_hs = line_h.iter().map(|&b| (b + b'0') as char).collect::<String>();
        let line_j = to_numeric_one(&line_hs);
        assert_eq!(line_j, vec![3, 1, 7, 8, 4, 2, 9, 5, 0, 6]);

        // Step 5: Chain addition 5 times
        //
        let mut r = line_h.clone();
        let mut all_digits: Vec<u8> = vec![];
        for _ in 0..5 {
            let inter = chainadd(&r);
            all_digits.extend(&inter);
            r = inter;
        }
        let line_p = r;
        let all_digits = all_digits.iter().map(|b| (*b + b'0') as char).collect::<String>();
        assert_eq!(all_digits, "50648055525602850077162035074878238571255051328370");

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

        // Line-P: 5 0 5 1 3 2 8 3 7 0
        // Line-S: 5 9 6 1 3 2 8 4 7 0 (to_numeric_one)
        //
        let line_ps = line_p.iter().map(|&b| (b + b'0') as char).collect::<String>();
        assert_eq!(line_ps, "5051328370");
        let line_s = to_numeric_one(&line_ps);

        assert_eq!(line_s, vec![5, 9, 6, 1, 3, 2, 8, 4, 7, 0]);

        // These digits are used for the second transposition key
        // And their numerical order for SC key.
        //
        let r_str: String = line_p.iter().map(|&b| (b + b'0') as char).collect();
        let sckey = to_numeric_one(&r_str);

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
        //
        assert_eq!(sckey, vec![0, 7, 9, 4, 1, 6, 3, 5, 8, 2]);
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
