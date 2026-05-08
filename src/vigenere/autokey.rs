//! Autokey cipher - an vigenere variant of the Vigenère cipher.
//!
//! The Autokey cipher is one of two vigenere systems invented by Vigenère himself. Unlike the
//! standard Vigenère cipher where the key repeats across the entire plaintext, the Autokey cipher
//! uses the plaintext itself to extend the key after the initial primer.
//!
//! # Algorithm
//!
//! Given a key K of length n and plaintext P:
//! - C₀ = P₀ ⊕ K₀
//! - C₁ = P₁ ⊕ K₁ (or P₀ if i >= n)
//! - ...
//! - Cᵢ = Pᵢ ⊕ Kᵢ (for i < n) or Pᵢ ⊕ Pᵢ₋ₙ (for i >= n)
//!
//! This can be visualized as:
//! ```text
//! Ciphertext = Plaintext ⊕ (Key || Plaintext)
//! ```
//!
//! The Autokey cipher is analogous to the CFB (Cipher Feedback) mode of operation in modern
//! block ciphers. It was designed to address the weakness of the standard Vigenère cipher's
//! repeating key, which is vulnerable to frequency analysis attacks like the Kasiski examination.
//!
//! # Historical Note
//!
//! Vigenère originally used a single-letter key (primer) for this system, which he called the
//! "vigenere" cipher. The key serves as an initialization vector (IV in modern terminology).
//!
//! # See Also
//! - [Autokey Cipher](https://en.wikipedia.org/wiki/Autokey_cipher)
//! - [`Autocrypt`](crate::vigenere::autocrypt::AutocryptCipher) - The ciphertext-based vigenere variant
//!

use std::marker::PhantomData;

use crate::Block;
use crate::helpers::{Alphabet, Latin26};
use crate::vigenere::plain::encode_one;

#[derive(Debug)]
pub struct Autokey<A: Alphabet> {
    /// The numeric key values (0..A::SIZE) derived from the key string.
    key: Vec<u8>,
    _phantom: PhantomData<A>,
}

/// Autokey cipher over the standard 26-letter Latin alphabet (A-Z).
pub type AutokeyCipher = Autokey<Latin26>;

impl<A: Alphabet> Autokey<A> {
    pub fn new(key: &str) -> Self {
        let key_vec = key.as_bytes().iter()
            .filter_map(|&b| A::normalize(b).map(|idx| idx as u8))
            .collect::<Vec<_>>();
        Autokey { key: key_vec, _phantom: PhantomData }
    }
}

impl<A: Alphabet> Block for Autokey<A> {
    fn block_size(&self) -> usize {
        1
    }

    /// Encrypts plaintext using the Autokey cipher.
    ///
    /// The autokey cipher uses the key for the first characters, then appends the plaintext
    /// itself to form an extended key. This creates a keystream that is as long as the message
    /// without repeating the original key.
    ///
    /// # Algorithm
    /// For each character at position i:
    /// - If i < key.len(): use key[i]
    /// - Otherwise: use plaintext[i - key.len()]
    ///
    /// Then apply standard Vigenère encryption: C[i] = (P[i] + K[i]) mod A::SIZE
    ///
    /// # Arguments
    /// * `dst` - Destination buffer where encrypted bytes will be written
    /// * `src` - Source plaintext bytes (expected to be in the alphabet)
    ///
    /// # Returns
    /// The length of the destination buffer
    ///
    /// # Examples
    /// ```rust
    /// # use old_crypto_rs::Block;
    /// # use old_crypto_rs::AutokeyCipher;
    ///
    /// let cipher = AutokeyCipher::new("KEY");
    /// let pt = b"HELLO";
    /// let mut ct = vec![0u8; pt.len()];
    /// cipher.encrypt(&mut ct, pt);
    /// assert_eq!(&ct, b"RIJSS");
    /// ```
    ///
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        if src.is_empty() {
            return 0;
        }
        let mut plain = Vec::with_capacity(src.len());
        let mut key: Vec<u8> = Vec::with_capacity(src.len());

        for (i, &p) in src.iter().enumerate() {
            if i >= dst.len() {
                break;
            }
            let p_val = match A::normalize(p) {
                Some(idx) => idx as u8,
                None => p,
            };
            plain.push(p_val);

            // Build the key: use original key for first few chars, then plaintext
            //
            if i < self.key.len() {
                key.push(self.key[i]);
            } else {
                // Use plaintext from (i - key.len()) positions back
                //
                key.push(plain[i - self.key.len()]);
            }
        }

        // We can use encode_one directly for the whole plaintext
        //
        let ct_vals = match encode_one::<A>(plain, key) {
            Ok(v) => v,
            Err(_) => return 0,
        };

        for (i, &val) in ct_vals.iter().enumerate() {
            dst[i] = A::denormalize(val as usize);
        }
        dst.len()
    }

    /// Decrypts ciphertext using the Autokey cipher.
    ///
    /// Reverses the autokey encryption process by using the key for the first characters,
    /// then using the previously decrypted plaintext to continue the keystream.
    ///
    /// # Algorithm
    /// For each character at position i:
    /// - If i < key.len(): use key[i]
    /// - Otherwise: use decrypted_plaintext[i - key.len()]
    /// - Decrypt: P[i] = (C[i] - K[i]) mod A::SIZE
    ///
    /// Each character must be decrypted in order since the plaintext is needed for the next key.
    ///
    /// # Arguments
    /// * `dst` - Destination buffer where decrypted bytes will be written
    /// * `src` - Source ciphertext bytes (expected to be in the alphabet)
    ///
    /// # Returns
    /// The number of bytes written to the destination buffer
    ///
    /// # Examples
    /// ```rust
    /// # use old_crypto_rs::Block;
    /// # use old_crypto_rs::AutokeyCipher;
    ///
    /// let cipher = AutokeyCipher::new("KEY");
    /// let ct = b"RIJSS";
    /// let mut pt = vec![0u8; ct.len()];
    /// cipher.decrypt(&mut pt, ct);
    /// assert_eq!(&pt, b"HELLO");
    /// ```
    ///
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        if src.is_empty() {
            return 0;
        }
        let n = A::SIZE as u8;
        let mut cipher = Vec::with_capacity(src.len());
        let mut plain = Vec::with_capacity(src.len());
        let mut neg_key = Vec::with_capacity(src.len());

        for (i, &c) in src.iter().enumerate() {
            if i >= dst.len() {
                break;
            }
            let c_val = match A::normalize(c) {
                Some(idx) => idx as u8,
                None => c,
            };
            cipher.push(c_val);

            // Build the negative key for decryption
            //
            let key_val = if i < self.key.len() {
                self.key[i]
            } else {
                // Use previously decrypted plaintext
                //
                plain[i - self.key.len()]
            };
            neg_key.push((n - key_val) % n);

            // Decrypt this character immediately so we can use it for the next key
            //
            let p_val = (c_val + neg_key[i]) % n;
            plain.push(p_val);
        }

        for (i, &val) in plain.iter().enumerate() {
            dst[i] = A::denormalize(val as usize);
        }

        plain.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_autokey_short() {
        let cipher = AutokeyCipher::new("KEY");
        let pt = b"HELLO";
        let mut ct = vec![0u8; pt.len()];
        cipher.encrypt(&mut ct, pt);
        assert_eq!(&ct, b"RIJSS");

        let mut dec = vec![0u8; ct.len()];
        cipher.decrypt(&mut dec, &ct);
        assert_eq!(&dec, pt);
    }

    #[test]
    fn test_autokey_longer_message() {
        let cipher = AutokeyCipher::new("FORTIFICATION");
        let pt = b"MEETMEATTHEGARDEN";
        let mut ct = vec![0u8; pt.len()];
        cipher.encrypt(&mut ct, pt);

        let mut dec = vec![0u8; ct.len()];
        cipher.decrypt(&mut dec, &ct);
        assert_eq!(&dec, pt);
    }

    #[test]
    fn test_autokey_single_char_key() {
        let cipher = AutokeyCipher::new("A");
        let pt = b"ATTACK";
        let mut ct = vec![0u8; pt.len()];
        cipher.encrypt(&mut ct, pt);
        // Keystream: A, A, T, T, A, C (key "A", then plaintext)
        // A+A=A, T+A=T, T+T=M, A+T=T, C+A=C, K+C=M
        //
        assert_eq!(&ct, b"ATMTCM");

        let mut dec = vec![0u8; ct.len()];
        cipher.decrypt(&mut dec, &ct);
        assert_eq!(&dec, pt);
    }

    #[test]
    fn test_autokey_key_longer_than_message() {
        let cipher = AutokeyCipher::new("VERYLONGKEY");
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
    fn test_autokey_repeated_chars() {
        let cipher = AutokeyCipher::new("B");
        let pt = b"AAAA";
        let mut ct = vec![0u8; pt.len()];
        cipher.encrypt(&mut ct, pt);
        // A(0) + B(1) = B(1)
        // A(0) + A(0) = A(0)
        // A(0) + A(0) = A(0)
        // A(0) + A(0) = A(0)
        //
        assert_eq!(&ct, b"BAAA");

        let mut dec = vec![0u8; ct.len()];
        cipher.decrypt(&mut dec, &ct);
        assert_eq!(&dec, pt);
    }

    #[test]
    fn test_autokey_empty_input() {
        let cipher = AutokeyCipher::new("KEY");
        let pt = b"";
        let mut ct = vec![0u8; pt.len()];
        let written = cipher.encrypt(&mut ct, pt);
        assert_eq!(written, 0);
    }

    #[test]
    fn test_autokey_all_zs() {
        let cipher = AutokeyCipher::new("Z");
        let pt = b"ZZZ";
        let mut ct = vec![0u8; pt.len()];
        cipher.encrypt(&mut ct, pt);
        // Z(25) + Z(25) = 50 % 26 = 24 = Y
        // Z(25) + Z(25) = 50 % 26 = 24 = Y
        // Z(25) + Z(25) = 50 % 26 = 24 = Y
        //
        assert_eq!(&ct, b"YYY");

        let mut dec = vec![0u8; ct.len()];
        cipher.decrypt(&mut dec, &ct);
        assert_eq!(&dec, pt);
    }

    #[test]
    fn test_autokey_wrap_around() {
        let cipher = AutokeyCipher::new("XYZ");
        let pt = b"ABCDE";
        let mut ct = vec![0u8; pt.len()];
        cipher.encrypt(&mut ct, pt);
        // A(0) + X(23) = 23 = X
        // B(1) + Y(24) = 25 = Z
        // C(2) + Z(25) = 27 % 26 = 1 = B
        // D(3) + A(0) = 3 = D
        // E(4) + B(1) = 5 = F
        //
        assert_eq!(&ct, b"XZBDF");

        let mut dec = vec![0u8; ct.len()];
        cipher.decrypt(&mut dec, &ct);
        assert_eq!(&dec, pt);
    }
}
