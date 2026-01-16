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
//! use old_crypto_rs::CaesarCipher;
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

/// A Caesar cipher implementation.
///
/// This struct maintains the shift key for the uppercase English alphabet (A-Z).
/// Characters not in the alphabet are left unchanged.
///
/// # Fields
///
/// * `enc` - Encryption lookup table mapping A-Z (0-25) to ciphertext
/// * `dec` - Decryption lookup table mapping A-Z (0-25) to plaintext
///
pub struct CaesarCipher {
    enc: [u8; 26],
    dec: [u8; 26],
}

impl CaesarCipher {
    /// Creates a new Caesar cipher with the specified shift key.
    ///
    /// The key represents how many positions each letter should be shifted in the alphabet.
    ///
    /// # Arguments
    ///
    /// * `key` - The shift value for the cipher (typically 0-25, but any integer works)
    ///
    /// # Returns
    ///
    /// A new `CaesarCipher` instance ready for encryption and decryption operations.
    ///
    /// # Examples
    ///
    /// ```
    /// use old_crypto_rs::CaesarCipher;
    ///
    /// let cipher = CaesarCipher::new(3); // Classic Caesar cipher with shift of 3
    /// ```
    ///
    pub fn new(key: i32) -> Self {
        let mut enc = [0u8; 26];
        let mut dec = [0u8; 26];
        let shift = (key % 26 + 26) % 26 as i32;
        for i in 0..26 {
            let e = (i as i32 + shift) % 26;
            enc[i] = (e as u8) + b'A';
            dec[e as usize] = (i as u8) + b'A';
        }
        CaesarCipher { enc, dec }
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
    /// Each byte in the source is shifted by the key value. Characters
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
            if ch.is_ascii_uppercase() {
                dst[i] = self.enc[(ch - b'A') as usize];
            } else {
                dst[i] = ch;
            }
        }
        src.len()
    }

    /// Decrypts the source data into the destination buffer.
    ///
    /// Each byte in the source is shifted back by the key value. Characters
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
            if ch.is_ascii_uppercase() {
                dst[i] = self.dec[(ch - b'A') as usize];
            } else {
                dst[i] = ch;
            }
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
    fn test_internal_mapping() {
        let c = CaesarCipher::new(3);
        assert_eq!(c.enc[(b'A' - b'A') as usize], b'D');
        assert_eq!(c.dec[(b'D' - b'A') as usize], b'A');
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
