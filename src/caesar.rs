//! Caesar cipher implementation.
//!
//! The Caesar cipher is one of the simplest and most widely known encryption techniques.
//! It is a type of substitution cipher in which each letter in the plaintext is replaced
//! by a letter some fixed number of positions down the alphabet.
//!
//! # Examples
//!
//! ```
//! use old_crypto_rs::Block;
//! use old_crypto_rs::caesar::CaesarCipher;
//!
//! let cipher = CaesarCipher::new(3);
//! let plaintext = b"HELLO";
//! let mut ciphertext = vec![0u8; plaintext.len()];
//!
//! cipher.encrypt(&mut ciphertext, plaintext);
//! assert_eq!(&ciphertext, b"KHOOR");
//!
//! let mut decrypted = vec![0u8; ciphertext.len()];
//! cipher.decrypt(&mut decrypted, &ciphertext);
//! assert_eq!(&decrypted, plaintext);
//! ```
//! 
use crate::Block;
use std::collections::HashMap;

const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ALPHABET_SIZE: usize = ALPHABET.len();

/// A Caesar cipher implementation using lookup tables.
///
/// This struct maintains encryption and decryption mappings for the uppercase
/// English alphabet (A-Z). Characters not in the alphabet are left unchanged.
///
/// # Fields
///
/// * `key` - The shift value used for the cipher (0-25)
/// * `enc` - Encryption lookup table mapping plaintext characters to ciphertext
/// * `dec` - Decryption lookup table mapping ciphertext characters to plaintext
///
pub struct CaesarCipher {
    #[allow(dead_code)]
    key: u8,
    enc: HashMap<u8, u8>,
    dec: HashMap<u8, u8>,
}

/// Expands the cipher key into encryption and decryption lookup tables.
///
/// This function populates the provided hash maps with the character mappings
/// needed for encryption and decryption. Each letter in the alphabet is shifted
/// by the key value (modulo 26) for encryption, and the reverse mapping is
/// created for decryption.
///
/// # Arguments
///
/// * `key` - The shift value for the Caesar cipher
/// * `enc` - Mutable reference to the encryption lookup table to populate
/// * `dec` - Mutable reference to the decryption lookup table to populate
///
fn expand_key(key: u8, enc: &mut HashMap<u8, u8>, dec: &mut HashMap<u8, u8>) {
    for (i, &ch) in ALPHABET.iter().enumerate() {
        let transform = (i + key as usize) % ALPHABET_SIZE;
        enc.insert(ch, ALPHABET[transform]);
        dec.insert(ALPHABET[transform], ch);
    }
}

impl CaesarCipher {
    /// Creates a new Caesar cipher with the specified shift key.
    ///
    /// The key value is converted to a u8 and used to generate the encryption
    /// and decryption lookup tables. The key effectively represents how many
    /// positions each letter should be shifted in the alphabet.
    ///
    /// # Arguments
    ///
    /// * `key` - The shift value for the cipher (typically 0-25, but larger values work due to modulo operation)
    ///
    /// # Returns
    ///
    /// A new `CaesarCipher` instance ready for encryption and decryption operations.
    ///
    /// # Examples
    ///
    /// ```
    /// use old_crypto_rs::caesar::CaesarCipher;
    ///
    /// let cipher = CaesarCipher::new(3); // Classic Caesar cipher with shift of 3
    /// ```
    ///
    pub fn new(key: i32) -> Self {
        let mut enc = HashMap::new();
        let mut dec = HashMap::new();
        let key_u8 = key as u8;
        expand_key(key_u8, &mut enc, &mut dec);
        CaesarCipher {
            key: key_u8,
            enc,
            dec,
        }
    }
}

impl Block for CaesarCipher {
    /// Returns the block size for the Caesar cipher.
    ///
    /// The Caesar cipher operates on single characters, so the block size is 1.
    fn block_size(&self) -> usize {
        1
    }

    /// Encrypts the source data into the destination buffer.
    ///
    /// Each byte in the source is looked up in the encryption table and the
    /// corresponding encrypted byte is written to the destination. Characters
    /// not in the alphabet (A-Z) are copied unchanged.
    ///
    /// # Arguments
    ///
    /// * `dst` - Destination buffer for encrypted data (must be at least as large as `src`)
    /// * `src` - Source data to encrypt
    ///
    /// # Returns
    ///
    /// The number of bytes written to the destination buffer (equal to `src.len()`).
    ///
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        for (i, &ch) in src.iter().enumerate() {
            dst[i] = *self.enc.get(&ch).unwrap_or(&ch);
        }
        src.len()
    }

    /// Decrypts the source data into the destination buffer.
    ///
    /// Each byte in the source is looked up in the decryption table and the
    /// corresponding decrypted byte is written to the destination. Characters
    /// not in the alphabet (A-Z) are copied unchanged.
    ///
    /// # Arguments
    ///
    /// * `dst` - Destination buffer for decrypted data (must be at least as large as `src`)
    /// * `src` - Source data to decrypt
    ///
    /// # Returns
    ///
    /// The number of bytes written to the destination buffer (equal to `src.len()`).
    /// 
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        for (i, &ch) in src.iter().enumerate() {
            dst[i] = *self.dec.get(&ch).unwrap_or(&ch);
        }
        src.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    #[rstest]
    #[case(3, "ABCDE", "DEFGH")]
    #[case(4, "COUCOU", "GSYGSY")]
    #[case(13, "COUCOU", "PBHPBH")]
    fn test_caesar_cipher_block_size(#[case] key: i32, #[case] _pt: &str, #[case] _ct: &str) {
        let c = CaesarCipher::new(key);
        assert_eq!(c.block_size(), 1);
    }

    #[test]
    fn test_expand_key() {
        let mut enc = HashMap::new();
        let mut dec = HashMap::new();

        let mut myenc = HashMap::new();
        let myenc_data = [
            (b'A', b'D'), (b'B', b'E'), (b'C', b'F'), (b'D', b'G'), (b'E', b'H'), (b'F', b'I'),
            (b'G', b'J'), (b'H', b'K'), (b'I', b'L'), (b'J', b'M'), (b'K', b'N'), (b'L', b'O'),
            (b'M', b'P'), (b'N', b'Q'), (b'O', b'R'), (b'P', b'S'), (b'Q', b'T'), (b'R', b'U'),
            (b'S', b'V'), (b'T', b'W'), (b'U', b'X'), (b'V', b'Y'), (b'W', b'Z'), (b'X', b'A'),
            (b'Y', b'B'), (b'Z', b'C'),
        ];
        for (k, v) in myenc_data { myenc.insert(k, v); }

        let mut mydec = HashMap::new();
        let mydec_data = [
            (b'D', b'A'), (b'E', b'B'), (b'F', b'C'), (b'G', b'D'), (b'H', b'E'), (b'I', b'F'),
            (b'J', b'G'), (b'K', b'H'), (b'L', b'I'), (b'M', b'J'), (b'N', b'K'), (b'O', b'L'),
            (b'P', b'M'), (b'Q', b'N'), (b'R', b'O'), (b'S', b'P'), (b'T', b'Q'), (b'U', b'R'),
            (b'V', b'S'), (b'W', b'T'), (b'X', b'U'), (b'Y', b'V'), (b'Z', b'W'), (b'A', b'X'),
            (b'B', b'Y'), (b'C', b'Z'),
        ];
        for (k, v) in mydec_data { mydec.insert(k, v); }

        expand_key(3, &mut enc, &mut dec);
        assert_eq!(myenc, enc);
        assert_eq!(mydec, dec);
    }

    #[rstest]
    #[case(3, "ABCDE", "DEFGH")]
    #[case(4, "COUCOU", "GSYGSY")]
    #[case(13, "COUCOU", "PBHPBH")]
    fn test_caesar_cipher_encrypt(#[case] key: i32, #[case] pt: &str, #[case] ct: &str) {
        let c = CaesarCipher::new(key);
        let plain = pt.as_bytes();
        let mut cipher = vec![0u8; plain.len()];
        c.encrypt(&mut cipher, plain);
        assert_eq!(cipher, ct.as_bytes());
    }

    #[rstest]
    #[case(3, "ABCDE", "DEFGH")]
    #[case(4, "COUCOU", "GSYGSY")]
    #[case(13, "COUCOU", "PBHPBH")]
    fn test_caesar_cipher_decrypt(#[case] key: i32, #[case] pt: &str, #[case] ct: &str) {
        let c = CaesarCipher::new(key);
        let cipher = ct.as_bytes();
        let mut plain = vec![0u8; cipher.len()];
        c.decrypt(&mut plain, cipher);
        assert_eq!(plain, pt.as_bytes());
    }
}
