//! This is yet another variation on the straddling checkerboard structure.
//!
//! To stay conform to the historical specs, the alphabet is not shuffled around, it
//! is just the labelling for the rows and cols that change according to the VIC key
//! expansion process.
//!
//! References: Kahn on Codes.
//!

use eyre::Result;

use crate::Block;
use crate::error::Error;
use crate::helpers::{Alphabet, Derive, EncEntry, Frequent};

use std::marker::PhantomData;

/// All cipher digits from 0 to 9 used in the checkerboard.
const ALL_CIPHER: &[u8] = b"0123456789";

/// A straddling checkerboard cipher implementation.
///
/// This cipher maps plaintext characters to variable-length digit sequences.
/// High-frequency letters are encoded as single digits, while low-frequency
/// letters are encoded as two digits prefixed by one of the "long" cipher digits.
///
/// # Examples
///
/// ```
/// use old_crypto_rs::EnglishStraddling;
/// use old_crypto_rs::Block;
///
/// let cipher = EnglishStraddling::new("ARABESQUE", "89").unwrap();
/// let mut encrypted = vec![0u8; 100];
/// let len = cipher.encrypt(&mut encrypted, b"ATTACK");
/// encrypted.truncate(len);
/// ```
///
#[derive(Debug)]
pub struct VicStraddling<A: Alphabet, D: Derive<F>, F: Frequent> {
    /// The two digits used as prefixes for two-digit codes (typically 2 bytes).
    longc: Vec<u8>,
    /// The shuffled alphabet after applying the key.
    full: String,
    /// Fast encoding table indexed by plaintext byte.
    enc_table: [EncEntry; 256],
    /// Fast decoding table for single-digit codes.
    dec1: [u8; 10],
    /// Fast decoding table for two-digit codes.
    dec2: [[u8; 10]; 10],
    /// Fast lookup for whether a digit is a long-code prefix.
    longc_mask: [bool; 10],
    /// The frequent letters.
    _marker: PhantomData<(A, D, F)>,
}

impl<A: Alphabet, D: Derive<F>, F: Frequent> std::fmt::Display for VicStraddling<A, D, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let longc = self.longc.iter().map(|&x| x as char).collect::<String>();
        let dec1 = self.dec1.iter().map(|&x| x as char).collect::<String>();
        let dec2 = self
            .dec2
            .iter()
            .map(|row| row.iter().map(|&x| x as char).collect::<String>())
            .filter(|row| !row.is_empty())
            .collect::<Vec<String>>();
        write!(
            f,
            "straddling full='{}', longc='{}', dec1='{}', dec2='{}'",
            self.full,
            longc,
            dec1,
            dec2.join(",")
        )
    }
}

impl<A: Alphabet, D: Derive<F>, F: Frequent> VicStraddling<A, D, F> {
    pub fn new(indexes: &str) -> Result<Self> {
        // Default alphabet.
        //
        let alphabet = match String::from_utf8(A::ALPHABET.to_vec()) {
            Ok(a) => a,
            Err(_) => return Err(Error::InvalidAlphabet.into()),
        };

        dbg!(&indexes);
        let longc = vec![indexes.as_bytes()[8], indexes.as_bytes()[9]];
        dbg!(String::from_utf8(longc.to_vec())?);

        // Shake the alphabet a bit
        //
        let full = String::from_utf8(D::derive(alphabet.as_bytes()))?;
        dbg!(&full);
        let shortc = indexes.as_bytes()[0..=7].to_vec();
        dbg!(String::from_utf8(shortc.to_vec())?);

        let mut c = VicStraddling {
            full,
            longc,
            enc_table: [EncEntry::default(); 256],
            dec1: [0; 10],
            dec2: [[0; 10]; 10],
            longc_mask: [false; 10],
            _marker: PhantomData,
        };
        for &c_digit in &c.longc {
            if c_digit.is_ascii_digit() {
                c.longc_mask[(c_digit - b'0') as usize] = true;
            }
        }
        c.expand_key(shortc, F::SYMBOLS);
        Ok(c)
    }

    /// Generates all two-digit combinations for a given prefix digit.
    ///
    /// Creates strings like "30", "31", ..., "39" for prefix '3'.
    /// Special case: if prefix is '0', returns single digits "0" through "9".
    ///
    /// # Arguments
    ///
    /// * `c` - The prefix digit
    ///
    /// # Returns
    ///
    /// A vector of 10 strings representing all combinations with this prefix.
    ///
    fn times10(c: u8) -> Vec<String> {
        let mut tmp = Vec::with_capacity(10);
        // if c == b'0' {
        //     for &b in ALL_CIPHER {
        //         tmp.push((b as char).to_string());
        //     }
        // } else {
            for &b in ALL_CIPHER {
                let mut s = (c as char).to_string();
                s.push(b as char);
                tmp.push(s);
            }
        //}
        tmp
    }

    /// Generates all two-digit combinations for both long cipher digits.
    ///
    /// Combines the results of `times10()` for both long cipher digits,
    /// producing 20 total two-digit codes.
    ///
    /// # Arguments
    ///
    /// * `set` - A slice containing the two long cipher digits
    ///
    /// # Returns
    ///
    /// A vector of 20 strings representing all two-digit codes.
    ///
    fn set_times10(set: &[u8]) -> Vec<String> {
        let mut longc = Vec::with_capacity(20);
        longc.extend(Self::times10(set[0]));
        longc.extend(Self::times10(set[1]));
        longc
    }

    /// Builds the encoding and decoding tables based on frequency analysis.
    ///
    /// Assigns single-digit codes to high-frequency letters and two-digit
    /// codes to low-frequency letters. Populates the encode/decode tables.
    ///
    /// # Arguments
    ///
    /// * `shortc` - The digits available for single-digit encoding
    /// * `freq` - The high-frequency letters that should get single-digit codes
    ///
    fn expand_key(&mut self, shortc: Vec<u8>, freq: &[u8]) {
        let longc = Self::set_times10(&self.longc);
        dbg!(longc.join(","));

        let mut i = 0;
        let mut j = 0;
        for &ch in self.full.as_bytes() {
            if freq.contains(&ch) {
                if i < shortc.len() {
                    let digit = shortc[i];
                    self.enc_table[ch as usize] = EncEntry::new(1, [digit, 0]);
                    self.dec1[(digit - b'0') as usize] = ch;
                    i += 1;
                }
            } else {
                if j < longc.len() {
                    let bytes = longc[j].as_bytes();
                    if bytes.len() == 2 {
                        let d0 = bytes[0];
                        let d1 = bytes[1];
                        self.enc_table[ch as usize] = EncEntry::new(2, [d0, d1]);
                        self.dec2[(d0 - b'0') as usize][(d1 - b'0') as usize] = ch;
                    }
                    j += 1;
                }
            }
        }
    }
}

impl<A: Alphabet, D: Derive<F>, F: Frequent> Block for VicStraddling<A, D, F> {
    /// Returns the block size, which equals the key length.
    ///
    /// # Returns
    ///
    /// The length of the cipher key in bytes.
    ///
    fn block_size(&self) -> usize {
        1
    }

    /// Encrypts plaintext into digit ciphertext.
    ///
    /// Each plaintext letter is replaced with its corresponding digit code
    /// (either 1 or 2 digits). Numeric digits in the plaintext are escaped
    /// by surrounding them with the '/' marker code and duplicating the digit.
    ///
    /// # Arguments
    ///
    /// * `dst` - Output buffer for the encrypted digit string
    /// * `src` - Input plaintext bytes to encrypt
    ///
    /// # Returns
    ///
    /// The number of bytes written to `dst`.
    ///
    /// # Examples
    ///
    /// Encrypting "ATTACK" with key "ARABESQUE" and long digits "89" produces "07708081".
    ///
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let mut offset = 0;
        let marker = self.enc_table[b'/' as usize];
        for &ch in src {
            if ch.is_ascii_digit() {
                if marker.len() != 0 {
                    dst[offset] = marker.bytes(0);
                    if marker.len() == 2 {
                        dst[offset + 1] = marker.bytes(1);
                    }
                    offset += marker.len() as usize;

                    dst[offset] = ch;
                    dst[offset + 1] = ch;
                    offset += 2;

                    dst[offset] = marker.bytes(0);
                    if marker.len() == 2 {
                        dst[offset + 1] = marker.bytes(1);
                    }
                    offset += marker.len() as usize;
                }
            } else {
                let entry = self.enc_table[ch as usize];
                dbg!(ch as char, &entry, offset);
                if entry.len() != 0 {
                    dst[offset] = entry.bytes(0);
                    if entry.len() == 2 {
                        dst[offset + 1] = entry.bytes(1);
                    }
                    offset += entry.len() as usize;
                }
            }
        }
        offset
    }

    /// Decrypts digit ciphertext back into plaintext.
    ///
    /// Processes the digit stream, recognizing both single-digit and two-digit
    /// codes. Handles escaped numeric digits by detecting the '/' marker pattern.
    ///
    /// # Arguments
    ///
    /// * `dst` - Output buffer for the decrypted plaintext
    /// * `src` - Input ciphertext digit string to decrypt
    ///
    /// # Returns
    ///
    /// The number of bytes written to `dst`.
    ///
    /// # Examples
    ///
    /// Decrypting "07708081" with key "ARABESQUE" and long digits "89" produces "ATTACK".
    ///
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let mut pt_offset = 0;
        let mut i = 0;
        while i < src.len() {
            let ch = src[i];
            let ptc;
            let mut db_len = 1;

            if !ch.is_ascii_digit() {
                i += 1;
                continue;
            }

            let d0 = (ch - b'0') as usize;
            if self.longc_mask[d0] {
                if i + 1 < src.len() {
                    let ch1 = src[i + 1];
                    if ch1.is_ascii_digit() {
                        let d1 = (ch1 - b'0') as usize;
                        ptc = self.dec2[d0][d1];
                        db_len = 2;
                    } else {
                        i += 2;
                        continue;
                    }
                } else {
                    i += 1;
                    continue;
                }
            } else {
                ptc = self.dec1[d0];
            }
            i += db_len;

            if ptc == b'/' {
                if i + 4 <= src.len() && src[i] == src[i + 1] {
                    let row0 = src[i + 2];
                    let row1 = src[i + 3];
                    if row0.is_ascii_digit() && row1.is_ascii_digit() {
                        let rd0 = (row0 - b'0') as usize;
                        let rd1 = (row1 - b'0') as usize;
                        let mut is_match = false;
                        if db_len == 2 {
                            is_match = row0 == src[i - 2] && row1 == src[i - 1];
                        }

                        if is_match || self.dec2[rd0][rd1] == b'/' {
                            if pt_offset < dst.len() {
                                dst[pt_offset] = src[i];
                                pt_offset += 1;
                            }
                            i += 4;
                            continue;
                        }
                    }
                }
            }
            if ptc != 0 {
                if pt_offset < dst.len() {
                    dst[pt_offset] = ptc;
                    pt_offset += 1;
                }
            }
        }
        pt_offset
    }
}

#[cfg(test)]
mod tests {
    use crate::helpers::{English, Horizontal, LatinSC};

    use super::*;
    use eyre::Result;

    #[test]
    fn test_vic_straddling_full() -> Result<()> {
        let pt1 = "ATTACKAT2AM";
        let ct1 = "1331919713882288199";
        const KEY2: &str = "1305427698";

        let cipher = VicStraddling::<LatinSC, Horizontal, English>::new(KEY2)?;
        println!("{}", cipher);

        let mut encrypted = vec![0u8; 100];
        let len = cipher.encrypt(&mut encrypted, pt1.as_bytes());
        encrypted.truncate(len);
        let enc_str = String::from_utf8(encrypted.to_vec())?;
        assert_eq!(ct1, enc_str);

        let mut decrypted = vec![0u8; 100];
        let len = cipher.decrypt(&mut decrypted, encrypted.as_slice());
        decrypted.truncate(len);
        let decr_str = String::from_utf8(decrypted)?;
        assert_eq!(pt1, decr_str);
        Ok(())
    }
}
