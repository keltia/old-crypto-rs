//! Autocrypt is the vigenere system where the ciphertext is used as key, instead of repeating the
//! key several times.  This is the equivalent on an IV in modern systems, and this is the ancestor
//! of the CBC mode for modern ciphers.
//!

use std::marker::PhantomData;

use crate::Block;
use crate::helpers::{Alphabet, Latin26};

#[derive(Debug)]
pub struct Autocrypt<A: Alphabet> {
    /// The numeric key values (0..A::SIZE) derived from the key string.
    ///
    key: Vec<u8>,
    _phantom: PhantomData<A>,
}

/// Autocrypt cipher over the standard 26-letter Latin alphabet (A-Z).
pub type AutocryptCipher = Autocrypt<Latin26>;

impl<A: Alphabet> Autocrypt<A> {
    pub fn new(key: &str) -> Self {
        let key_vec = key.as_bytes().iter()
            .filter_map(|&b| A::normalize(b).map(|idx| idx as u8))
            .collect::<Vec<_>>();
        Autocrypt { key: key_vec, _phantom: PhantomData }
    }
}

impl<A: Alphabet> Block for Autocrypt<A> {
    fn block_size(&self) -> usize {
        1
    }

    /// Encrypts plaintext using the Autocrypt cipher with ciphertext feedback.
    ///
    /// This method implements the autocrypt encryption scheme where:
    /// - The first `key.len()` characters are encrypted using the original key
    /// - Subsequent characters use previously generated ciphertext as the key (CBC-like mode)
    ///
    /// # Arguments
    ///
    /// * `dst` - The destination buffer where ciphertext will be written
    /// * `src` - The source plaintext to encrypt (assumes alphabet characters)
    ///
    /// # Returns
    ///
    /// The number of bytes written to `dst`, which is `min(src.len(), dst.len())`
    ///
    /// # Example
    ///
    /// ```rust
    /// use old_crypto_rs::AutocryptCipher;
    /// use old_crypto_rs::Block;
    ///
    /// let cipher = AutocryptCipher::new("KEY");
    /// let plaintext = b"HELLO";
    /// let mut ciphertext = vec![0u8; plaintext.len()];
    /// cipher.encrypt(&mut ciphertext, plaintext);
    /// assert_eq!(&ciphertext, b"RIJCW");
    /// ```
    ///
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        if src.is_empty() {
            return 0;
        }

        let n = A::SIZE as u8;
        for (i, &p) in src.iter().enumerate() {
            if i >= dst.len() {
                break;
            }
            let p_val = match A::normalize(p) {
                Some(idx) => idx as u8,
                None => p,
            };

            // Build the key: use original key for first few chars, then ciphertext
            //
            let key_val = if i < self.key.len() {
                self.key[i]
            } else {
                // Use previously encrypted ciphertext (CBC mode)
                // dst[i - self.key.len()] is already encrypted; normalize it back to 0..n
                //
                A::normalize(dst[i - self.key.len()]).unwrap_or(0) as u8
            };

            // Encrypt this character
            //
            let c_val = (p_val + key_val) % n;
            dst[i] = A::denormalize(c_val as usize);
        }

        src.len().min(dst.len())
    }

    /// Decrypts ciphertext using the Autocrypt cipher with ciphertext feedback.
    ///
    /// This method implements the autocrypt decryption scheme where:
    /// - The first `key.len()` characters are decrypted using the original key
    /// - Subsequent characters use previously processed ciphertext as the key (CBC-like mode)
    ///
    /// # Arguments
    ///
    /// * `dst` - The destination buffer where plaintext will be written
    /// * `src` - The source ciphertext to decrypt (assumes alphabet characters)
    ///
    /// # Returns
    ///
    /// The number of bytes written to `dst`, which is `min(src.len(), dst.len())`
    ///
    /// # Example
    ///
    /// ```rust
    /// use old_crypto_rs::AutocryptCipher;
    /// use old_crypto_rs::Block;
    ///
    /// let cipher = AutocryptCipher::new("KEY");
    /// let ciphertext = b"RIJCW";
    /// let mut plaintext = vec![0u8; ciphertext.len()];
    /// cipher.decrypt(&mut plaintext, ciphertext);
    /// assert_eq!(&plaintext, b"HELLO");
    /// ```
    ///
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        if src.is_empty() {
            return 0;
        }

        let n = A::SIZE as u8;
        for (i, &c) in src.iter().enumerate() {
            if i >= dst.len() {
                break;
            }
            let c_val = match A::normalize(c) {
                Some(idx) => idx as u8,
                None => c,
            };

            // Build the key: use original key for first few chars, then ciphertext
            //
            let key_val = if i < self.key.len() {
                self.key[i]
            } else {
                // Use previous ciphertext value for the key
                //
                A::normalize(src[i - self.key.len()]).unwrap_or(0) as u8
            };

            // Decrypt this character
            //
            let p_val = (c_val + n - key_val) % n;
            dst[i] = A::denormalize(p_val as usize);
        }

        src.len().min(dst.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_autocrypt_basic() {
        let cipher = AutocryptCipher::new("KEY");
        let pt = b"HELLO";
        let mut ct = vec![0u8; pt.len()];
        cipher.encrypt(&mut ct, pt);

        // Keystream: K, E, Y, R, I (key "KEY", then ciphertext "RI...")
        // H(7) + K(10) = 17 = R
        // E(4) + E(4) = 8 = I
        // L(11) + Y(24) = 35 % 26 = 9 = J
        // L(11) + R(17) = 28 % 26 = 2 = C
        // O(14) + I(8) = 22 = W
        //
        assert_eq!(&ct, b"RIJCW");

        let mut dec = vec![0u8; ct.len()];
        cipher.decrypt(&mut dec, &ct);
        assert_eq!(&dec, pt);
    }

    #[test]
    fn test_autocrypt_longer_message() {
        let cipher = AutocryptCipher::new("SECRET");
        let pt = b"ATTACKATDAWN";
        let mut ct = vec![0u8; pt.len()];
        cipher.encrypt(&mut ct, pt);

        let mut dec = vec![0u8; ct.len()];
        cipher.decrypt(&mut dec, &ct);
        assert_eq!(&dec, pt);
    }

    #[test]
    fn test_autocrypt_single_char_key() {
        let cipher = AutocryptCipher::new("A");
        let pt = b"ATTACK";
        let mut ct = vec![0u8; pt.len()];
        cipher.encrypt(&mut ct, pt);

        // Keystream: A, A, T, M, M, O (key "A", then ciphertext "ATMMO")
        // A(0) + A(0) = 0 = A
        // T(19) + A(0) = 19 = T
        // T(19) + T(19) = 38 % 26 = 12 = M
        // A(0) + M(12) = 12 = M
        // C(2) + M(12) = 14 = O
        // K(10) + O(14) = 24 = Y
        //
        assert_eq!(&ct, b"ATMMOY");

        let mut dec = vec![0u8; ct.len()];
        cipher.decrypt(&mut dec, &ct);
        assert_eq!(&dec, pt);
    }

    #[test]
    fn test_autocrypt_key_longer_than_message() {
        let cipher = AutocryptCipher::new("VERYLONGKEY");
        let pt = b"HI";
        let mut ct = vec![0u8; pt.len()];
        cipher.encrypt(&mut ct, pt);
        // H(7) + V(21) = 28 % 26 = 2 = C
        // I(8) + E(4) = 12 = M
        //
        assert_eq!(&ct, b"CM");

        let mut dec = vec![0u8; ct.len()];
        cipher.decrypt(&mut dec, &ct);
        assert_eq!(&dec, pt);
    }

    #[test]
    fn test_autocrypt_repeated_chars() {
        let cipher = AutocryptCipher::new("B");
        let pt = b"AAAA";
        let mut ct = vec![0u8; pt.len()];
        cipher.encrypt(&mut ct, pt);

        // Keystream: B, B, B, B (key "B", then ciphertext "BBB")
        // A(0) + B(1) = 1 = B
        // A(0) + B(1) = 1 = B
        // A(0) + B(1) = 1 = B
        // A(0) + B(1) = 1 = B
        //
        assert_eq!(&ct, b"BBBB");

        let mut dec = vec![0u8; ct.len()];
        cipher.decrypt(&mut dec, &ct);
        assert_eq!(&dec, pt);
    }

    #[test]
    fn test_autocrypt_empty_input() {
        let cipher = AutocryptCipher::new("KEY");
        let pt = b"";
        let mut ct = vec![0u8; pt.len()];
        let written = cipher.encrypt(&mut ct, pt);
        assert_eq!(written, 0);
    }

    #[test]
    fn test_autocrypt_wrap_around() {
        let cipher = AutocryptCipher::new("XYZ");
        let pt = b"ABCDE";
        let mut ct = vec![0u8; pt.len()];
        cipher.encrypt(&mut ct, pt);

        // A(0) + X(23) = 23 = X
        // B(1) + Y(24) = 25 = Z
        // C(2) + Z(25) = 27 % 26 = 1 = B
        // D(3) + X(23) = 26 % 26 = 0 = A
        // E(4) + Z(25) = 29 % 26 = 3 = D
        //
        assert_eq!(&ct, b"XZBAD");

        let mut dec = vec![0u8; ct.len()];
        cipher.decrypt(&mut dec, &ct);
        assert_eq!(&dec, pt);
    }

    #[test]
    fn test_autocrypt_vs_autokey_different() {
        // Autocrypt (ciphertext feedback) should produce different output than Autokey (plaintext feedback)
        //
        use crate::vigenere::autokey::AutokeyCipher;

        let autocrypt = AutocryptCipher::new("KEY");
        let autokey = AutokeyCipher::new("KEY");
        let pt = b"HELLO";

        let mut ct_autocrypt = vec![0u8; pt.len()];
        autocrypt.encrypt(&mut ct_autocrypt, pt);

        let mut ct_autokey = vec![0u8; pt.len()];
        autokey.encrypt(&mut ct_autokey, pt);

        // They should produce different ciphertexts
        //
        assert_ne!(&ct_autocrypt, &ct_autokey);
        assert_eq!(&ct_autocrypt, b"RIJCW"); // ciphertext feedback
        assert_eq!(&ct_autokey, b"RIJSS");   // plaintext feedback
    }

    #[test]
    fn test_autocrypt_all_zs() {
        let cipher = AutocryptCipher::new("Z");
        let pt = b"ZZZ";
        let mut ct = vec![0u8; pt.len()];
        cipher.encrypt(&mut ct, pt);

        // Z(25) + Z(25) = 50 % 26 = 24 = Y
        // Z(25) + Y(24) = 49 % 26 = 23 = X
        // Z(25) + X(23) = 48 % 26 = 22 = W
        //
        assert_eq!(&ct, b"YXW");

        let mut dec = vec![0u8; ct.len()];
        cipher.decrypt(&mut dec, &ct);
        assert_eq!(&dec, pt);
    }

    #[test]
    fn test_autocrypt_long_text() {
        let cipher = AutocryptCipher::new("CRYPTOGRAPHY");
        let pt = b"THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG";
        let mut ct = vec![0u8; pt.len()];
        cipher.encrypt(&mut ct, pt);

        let mut dec = vec![0u8; ct.len()];
        cipher.decrypt(&mut dec, &ct);
        assert_eq!(&dec, pt);
    }
}
