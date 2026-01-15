//! Transposition cipher implementation.
//!
//! This module implements a columnar transposition cipher, which rearranges the plaintext
//! by writing it in rows of a fixed length (determined by the key), then reading out the
//! columns in an order determined by the alphabetical order of the key letters.
//!
//! # Examples
//!
//! ```
//! use old_crypto_rs::{Block, Transposition};
//!
//! let cipher = Transposition::new("ZEBRAS").unwrap();
//! let plaintext = b"WEAREDISCOVEREDFLEEATONCE";
//! let mut ciphertext = vec![0u8; plaintext.len()];
//! cipher.encrypt(&mut ciphertext, plaintext);
//! ```
//!
use crate::Block;
use crate::helpers;

/// A columnar transposition cipher.
///
/// The transposition cipher rearranges the positions of characters in plaintext
/// according to a regular system. This implementation uses a keyword to determine
/// the column order for reading the transposed text.
///
/// # Fields
///
/// * `key` - The original keyword string used for the cipher
/// * `tkey` - The numeric representation of the key, where each character is converted
///           to its alphabetical position (0-based)
///
#[derive(Debug)]
pub struct Transposition {
    #[allow(dead_code)]
    key: String,
    tkey: Vec<u8>,
}

impl Transposition {
    /// Creates a new Transposition cipher with the given key.
    ///
    /// The key determines the order in which columns are read during encryption and
    /// written during decryption. The key is converted to a numeric representation
    /// where each character's alphabetical position determines the column order.
    ///
    /// # Arguments
    ///
    /// * `key` - A non-empty string used as the cipher key
    ///
    /// # Returns
    ///
    /// * `Ok(Transposition)` - Successfully created cipher instance
    /// * `Err(String)` - If the key is empty
    ///
    /// # Examples
    ///
    /// ```
    /// use old_crypto_rs::{Block, Transposition};
    ///
    /// let cipher = Transposition::new("ZEBRAS").unwrap();
    /// assert_eq!(cipher.block_size(), 6);
    /// ```
    ///
    pub fn new(key: &str) -> Result<Self, String> {
        if key.is_empty() {
            return Err("key can not be empty".to_string());
        }

        Ok(Transposition {
            key: key.to_string(),
            tkey: helpers::to_numeric(key),
        })
    }
}

impl Block for Transposition {
    /// Returns the block size of this cipher.
    ///
    /// For the transposition cipher, the block size equals the length of the key,
    /// which determines how many columns are used in the transposition table.
    ///
    /// # Returns
    ///
    /// The number of columns used in the transposition (key length)
    ///
    fn block_size(&self) -> usize {
        self.tkey.len()
    }

    /// Encrypts plaintext using the transposition cipher.
    ///
    /// The encryption process:
    /// 1. Writes the plaintext into a table row by row, with column count equal to key length
    /// 2. Reads the columns in the order determined by the alphabetical order of the key
    /// 3. Concatenates the columns to form the ciphertext
    ///
    /// # Arguments
    ///
    /// * `dst` - Destination buffer for the encrypted output (must be at least as large as `src`)
    /// * `src` - Source plaintext to encrypt
    ///
    /// # Returns
    ///
    /// The number of bytes written to `dst` (equal to `src.len()`)
    ///
    /// # Examples
    ///
    /// ```
    /// use old_crypto_rs::{Block, Transposition};
    ///
    /// let cipher = Transposition::new("SUBWAY").unwrap();
    /// let plaintext = b"AVAGAGAVDFFGAVAGDGAVGVFX";
    /// let mut ciphertext = vec![0u8; plaintext.len()];
    /// cipher.encrypt(&mut ciphertext, plaintext);
    /// ```
    ///
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let klen = self.tkey.len();
        let mut table = vec![Vec::new(); klen];

        // Fill-in the table
        for (i, &ch) in src.iter().enumerate() {
            table[i % klen].push(ch);
        }

        let mut res = Vec::with_capacity(src.len());
        // Extract each column in order
        for i in 0..klen {
            let j = self.tkey.iter().position(|&x| x == i as u8).unwrap();
            res.extend_from_slice(&table[j]);
        }
        dst[..res.len()].copy_from_slice(&res);
        res.len()
    }

    /// Decrypts ciphertext using the transposition cipher.
    ///
    /// The decryption process:
    /// 1. Determines the dimensions of the transposition table
    /// 2. Distributes the ciphertext into columns according to the key order
    /// 3. Handles irregular tables where some columns may be shorter
    /// 4. Reads the table row by row to reconstruct the plaintext
    ///
    /// # Arguments
    ///
    /// * `dst` - Destination buffer for the decrypted output (must be at least as large as `src`)
    /// * `src` - Source ciphertext to decrypt
    ///
    /// # Returns
    ///
    /// The number of bytes written to `dst` (equal to `src.len()`)
    ///
    /// # Examples
    ///
    /// ```
    /// use old_crypto_rs::{Block, Transposition};
    ///
    /// let cipher = Transposition::new("SUBWAY").unwrap();
    /// let ciphertext = b"AFDFADAGAAAAVVVVGFGVGGGX";
    /// let mut plaintext = vec![0u8; ciphertext.len()];
    /// cipher.decrypt(&mut plaintext, ciphertext);
    /// ```
    ///
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let klen = self.tkey.len();
        let mut table = vec![Vec::new(); klen];
        let scol = (src.len() + klen - 1) / klen;

        // Find how many columns are not filled in (irregular table)
        let pad = src.len() % klen; // col 0..pad-1 are complete
        let _num_complete = if pad == 0 { klen } else { pad };

        let mut current = 0;
        for j in 0..klen {
            let ind = self.tkey.iter().position(|&x| x == j as u8).unwrap();
            
            let mut how_many = scol;
            if pad != 0 && ind >= pad {
                how_many -= 1;
            }

            if current + how_many <= src.len() {
                table[ind].extend_from_slice(&src[current..current + how_many]);
                current += how_many;
            }
        }

        // Now get all text
        for i in 0..src.len() {
            let col = i % klen;
            let row = i / klen;
            if row < table[col].len() {
                dst[i] = table[col][row];
            }
        }
        src.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    #[test]
    fn test_new_cipher() {
        let c = Transposition::new("ABCDE").unwrap();
        assert_eq!(c.key, "ABCDE");
        assert_eq!(c.tkey, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn test_new_cipher_empty() {
        let c = Transposition::new("");
        assert!(c.is_err());
    }

    #[test]
    fn test_transposition_block_size() {
        let c = Transposition::new("ABCDE").unwrap();
        assert_eq!(c.block_size(), 5);
    }

    #[rstest]
    #[case("ARABESQUE", "AATNIITN2MIHAAXOOTCT2RNXDNENNAOXMB2TW4DTGKP3ES1TISUY3", "ATTACKATDAWNATPOINT42X23XSENDMOREMUNITIONSBYNIGHTX123")]
    #[case("SUBWAY", "CWI2DUNG3TDP2EEIN1AAATXOIBTTTT4SRTYXAAOXNMOI2KNN3MNSH", "ATTACKATDAWNATPOINT42X23XSENDMOREMUNITIONSBYNIGHTX123")]
    #[case("PORTABLE", "CA2DIN3KTXMTITO3ROHAP2OIGTANSMSXADIXENTTWTEUB1AN4NNY2", "ATTACKATDAWNATPOINT42X23XSENDMOREMUNITIONSBYNIGHTX123")]
    #[case("SUBWAY", "AFDFADAGAAAAVVVVGFGVGGGX", "AVAGAGAVDFFGAVAGDGAVGVFX")]
    fn test_transposition_encrypt(#[case] key: &str, #[case] ct: &str, #[case] pt: &str) {
        let c = Transposition::new(key).unwrap();
        let mut dst = vec![0u8; pt.len()];
        c.encrypt(&mut dst, pt.as_bytes());
        assert_eq!(String::from_utf8(dst).unwrap(), ct);
    }

    #[rstest]
    #[case("ARABESQUE", "AATNIITN2MIHAAXOOTCT2RNXDNENNAOXMB2TW4DTGKP3ES1TISUY3", "ATTACKATDAWNATPOINT42X23XSENDMOREMUNITIONSBYNIGHTX123")]
    #[case("SUBWAY", "CWI2DUNG3TDP2EEIN1AAATXOIBTTTT4SRTYXAAOXNMOI2KNN3MNSH", "ATTACKATDAWNATPOINT42X23XSENDMOREMUNITIONSBYNIGHTX123")]
    #[case("PORTABLE", "CA2DIN3KTXMTITO3ROHAP2OIGTANSMSXADIXENTTWTEUB1AN4NNY2", "ATTACKATDAWNATPOINT42X23XSENDMOREMUNITIONSBYNIGHTX123")]
    #[case("SUBWAY", "AFDFADAGAAAAVVVVGFGVGGGX", "AVAGAGAVDFFGAVAGDGAVGVFX")]
    fn test_transposition_decrypt(#[case] key: &str, #[case] ct: &str, #[case] pt: &str) {
        let c = Transposition::new(key).unwrap();
        let mut dst = vec![0u8; pt.len()];
        c.decrypt(&mut dst, ct.as_bytes());
        assert_eq!(String::from_utf8(dst).unwrap(), pt);
    }
}
