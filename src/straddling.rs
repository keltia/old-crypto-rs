//! Straddling Checkerboard cipher implementation.
//!
//! The straddling checkerboard is a substitution cipher that uses a 10-column grid
//! to encode letters into digits. Common letters are encoded as single digits,
//! while less common letters require two digits. This creates variable-length
//! ciphertext that appears as a stream of digits.
//!
//! The cipher uses:
//! - A keyword to shuffle the alphabet
//! - Two "long" cipher digits that prefix two-digit codes
//! - Eight "short" cipher digits for single-digit codes
//! - A frequency string to determine which letters get single-digit codes
//!
use crate::Block;
use crate::helpers;
use std::collections::HashMap;

/// Default alphabet containing A-Z plus special characters '/' and '-'.
/// The '/' character is used as a digit escape marker in encryption.
pub const ALPHABET_TXT: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ/-";

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
/// use old_crypto_rs::StraddlingCheckerboard;
/// use old_crypto_rs::Block;
///
/// let cipher = StraddlingCheckerboard::new("ARABESQUE", "89").unwrap();
/// let mut encrypted = vec![0u8; 100];
/// let len = cipher.encrypt(&mut encrypted, b"ATTACK");
/// encrypted.truncate(len);
/// ```
///
#[derive(Debug)]
pub struct StraddlingCheckerboard {
    /// The keyword used to shuffle the alphabet.
    key: String,
    /// The two digits used as prefixes for two-digit codes (typically 2 bytes).
    longc: Vec<u8>,
    /// The eight digits used for single-digit codes (not currently used in implementation).
    #[allow(dead_code)]
    shortc: Vec<u8>,
    /// The shuffled alphabet after applying the key.
    full: String,
    /// Encoding map from plaintext byte to ciphertext digit string.
    pub enc: HashMap<u8, String>,
    /// Decoding map from ciphertext digit string to plaintext byte.
    pub dec: HashMap<String, u8>,
}

impl StraddlingCheckerboard {
    /// Creates a new straddling checkerboard cipher with default frequency.
    ///
    /// Uses "ESANTIRU" as the default high-frequency letters and the standard
    /// alphabet (A-Z plus '/' and '-').
    ///
    /// # Arguments
    ///
    /// * `key` - The keyword used to shuffle the alphabet (must not be empty)
    /// * `chrs` - A string of at least 2 digits that will be used as "long" cipher digits
    ///
    /// # Returns
    ///
    /// Returns `Ok(StraddlingCheckerboard)` on success, or `Err(String)` if validation fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `key` is empty
    /// - `chrs` contains fewer than 2 characters
    ///
    /// # Examples
    ///
    /// ```
    /// use old_crypto_rs::StraddlingCheckerboard;
    ///
    /// let cipher = StraddlingCheckerboard::new("ARABESQUE", "89").unwrap();
    /// ```
    ///
    pub fn new(key: &str, chrs: &str) -> Result<Self, String> {
        Self::new_with_freq(key, chrs, "ESANTIRU", ALPHABET_TXT)
    }

    /// Creates a new straddling checkerboard cipher with custom frequency and alphabet.
    ///
    /// Allows full customization of which letters get single-digit codes and
    /// what alphabet to use.
    ///
    /// # Arguments
    ///
    /// * `key` - The keyword used to shuffle the alphabet (must not be empty)
    /// * `chrs` - A string of at least 2 digits for "long" cipher digit prefixes
    /// * `freq_str` - Letters that should receive single-digit encodings
    /// * `alphabet` - The alphabet to use for the checkerboard
    ///
    /// # Returns
    ///
    /// Returns `Ok(StraddlingCheckerboard)` on success, or `Err(String)` if validation fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `key` is empty
    /// - `chrs` contains fewer than 2 characters
    ///
    pub fn new_with_freq(key: &str, chrs: &str, freq_str: &str, alphabet: &str) -> Result<Self, String> {
        if key.is_empty() {
            return Err("key can not be empty".to_string());
        }
        if chrs.len() < 2 {
            return Err("longc must have at least 2 characters".to_string());
        }

        let longc = vec![chrs.as_bytes()[0], chrs.as_bytes()[1]];
        let full = if key.is_empty() {
            alphabet.to_string()
        } else {
            helpers::shuffle(key, alphabet)
        };
        // Remove digits from full if they were added by the key but not in the alphabet
        let full_clean: String = full.chars().filter(|&c| alphabet.contains(c)).collect();
        let shortc = Self::extract(ALL_CIPHER, &longc);

        let mut c = StraddlingCheckerboard {
            key: key.to_string(),
            full: full_clean,
            longc,
            shortc: shortc.clone(),
            enc: HashMap::new(),
            dec: HashMap::new(),
        };
        c.expand_key(shortc, freq_str.as_bytes());
        Ok(c)
    }

    /// Extracts elements from a set that are not in the exclusion list.
    ///
    /// Used to compute the "short" cipher digits by removing the "long" digits
    /// from all possible cipher digits.
    ///
    /// # Arguments
    ///
    /// * `set` - The full set of digits (0-9)
    /// * `two` - The two digits to exclude
    ///
    /// # Returns
    ///
    /// A vector containing all digits from `set` except those in `two`.
    ///
    fn extract(set: &[u8], two: &[u8]) -> Vec<u8> {
        set.iter().cloned().filter(|&x| !two.contains(&x)).collect()
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
        if c == b'0' {
            for &b in ALL_CIPHER {
                tmp.push((b as char).to_string());
            }
        } else {
            for &b in ALL_CIPHER {
                let mut s = (c as char).to_string();
                s.push(b as char);
                tmp.push(s);
            }
        }
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

    /// Builds the encoding and decoding maps based on frequency analysis.
    ///
    /// Assigns single-digit codes to high-frequency letters and two-digit
    /// codes to low-frequency letters. Populates both the `enc` and `dec`
    /// hashmaps.
    ///
    /// # Arguments
    ///
    /// * `shortc` - The digits available for single-digit encoding
    /// * `freq` - The high-frequency letters that should get single-digit codes
    ///
    fn expand_key(&mut self, shortc: Vec<u8>, freq: &[u8]) {
        let longc = Self::set_times10(&self.longc);

        let mut i = 0;
        let mut j = 0;
        for &ch in self.full.as_bytes() {
            if freq.contains(&ch) {
                if i < shortc.len() {
                    let s = (shortc[i] as char).to_string();
                    self.enc.insert(ch, s.clone());
                    self.dec.insert(s, ch);
                    i += 1;
                }
            } else {
                if j < longc.len() {
                    let s = longc[j].clone();
                    self.enc.insert(ch, s.clone());
                    self.dec.insert(s, ch);
                    j += 1;
                }
            }
        }
    }
}

impl Block for StraddlingCheckerboard {
    /// Returns the block size, which equals the key length.
    ///
    /// # Returns
    ///
    /// The length of the cipher key in bytes.
    ///
    fn block_size(&self) -> usize {
        self.key.len()
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
        for &ch in src {
            if ch.is_ascii_digit() {
                let marker = self.enc.get(&b'/').unwrap();
                dst[offset..offset + marker.len()].copy_from_slice(marker.as_bytes());
                offset += marker.len();
                
                dst[offset] = ch;
                dst[offset + 1] = ch;
                offset += 2;
                
                dst[offset..offset + marker.len()].copy_from_slice(marker.as_bytes());
                offset += marker.len();
            } else if let Some(s) = self.enc.get(&ch) {
                let s_bytes = s.as_bytes();
                dst[offset..offset + s_bytes.len()].copy_from_slice(s_bytes);
                offset += s_bytes.len();
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
            let mut ptc;
            let mut db_str = String::new();

            if self.longc.contains(&ch) {
                if i + 1 < src.len() {
                    db_str.push(ch as char);
                    db_str.push(src[i + 1] as char);
                    ptc = *self.dec.get(&db_str).unwrap_or(&0);
                    i += 2;
                } else {
                    i += 1;
                    continue;
                }
            } else {
                db_str.push(ch as char);
                ptc = *self.dec.get(&db_str).unwrap_or(&0);
                i += 1;
            }

            if ptc == b'/' {
                if i + 4 <= src.len() {
                    let numb = &src[i..i+4];
                    if numb[0] == numb[1] {
                        let row_check = (numb[2] as char).to_string() + &(numb[3] as char).to_string();
                        if row_check == db_str || self.dec.get(&row_check) == Some(&b'/') {
                            ptc = numb[0];
                            i += 4;
                        }
                    }
                }
            }
            if ptc != 0 {
                dst[pt_offset] = ptc;
                pt_offset += 1;
            }
        }
        pt_offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    #[test]
    fn test_new_cipher() {
        let c = StraddlingCheckerboard::new("ARABESQUE", "89").unwrap();
        assert_eq!(c.full, "ACKVRDLWBFMXEGNYSHOZQIP/UJT-");
        assert_eq!(c.shortc, b"01234567");
        assert_eq!(c.longc, b"89");
    }

    #[test]
    fn test_new_cipher_bad_keys() {
        assert!(StraddlingCheckerboard::new("ARABESQUE", "").is_err());
        assert!(StraddlingCheckerboard::new("", "89").is_err());
    }

    #[test]
    fn test_expand_key() {
        let c = StraddlingCheckerboard::new("ARABESQUE", "89").unwrap();
        assert_eq!(c.enc.get(&b'V').unwrap(), "82");
        assert_eq!(c.enc.get(&b'K').unwrap(), "81");
        assert_eq!(c.enc.get(&b'A').unwrap(), "0");
        assert_eq!(c.enc.get(&b'E').unwrap(), "2");
        assert_eq!(c.dec.get("82").unwrap(), &b'V');
        assert_eq!(c.dec.get("0").unwrap(), &b'A');
    }

    #[rstest]
    #[case(b'3', vec!["30", "31", "32", "33", "34", "35", "36", "37", "38", "39"])]
    #[case(b'1', vec!["10", "11", "12", "13", "14", "15", "16", "17", "18", "19"])]
    fn test_times10(#[case] c: u8, #[case] expected: Vec<&str>) {
        assert_eq!(StraddlingCheckerboard::times10(c), expected);
    }

    #[rstest]
    #[case(b"25", b"01346789")]
    #[case(b"16", b"02345789")]
    #[case(b"42", b"01356789")]
    fn test_extract(#[case] two: &[u8], #[case] expected: &[u8]) {
        assert_eq!(StraddlingCheckerboard::extract(ALL_CIPHER, two), expected);
    }

    #[rstest]
    #[case("ARABESQUE", "89", "ATTACKAT2AM", "0770808107972297088")]
    #[case("ARABESQUE", "36", "ATTACKAT2AM", "0990303109672267038")]
    #[case("ARABESQUE", "37", "IFYOUCANREADTHIS", "6377173830041203397265")]
    #[case("ARABESQUE", "89", "ATTACK", "07708081")]
    #[case("SUBWAY", "89", "TOLKIEN", "6819388137")]
    #[case("PORTABLE", "89", "RETRIBUTION", "1721693526840")]
    fn test_straddling_encrypt(#[case] key: &str, #[case] chrs: &str, #[case] pt: &str, #[case] ct: &str) {
        let c = StraddlingCheckerboard::new(key, chrs).unwrap();
        let mut dst = vec![0u8; 100];
        c.encrypt(&mut dst, pt.as_bytes());
        let sct = String::from_utf8_lossy(&dst).trim_matches('\0').to_string();
        assert_eq!(sct, ct);
    }

    #[rstest]
    #[case("ARABESQUE", "89", "ATTACKAT2AM", "0770808107972297088")]
    #[case("ARABESQUE", "36", "ATTACKAT2AM", "0990303109672267038")]
    #[case("ARABESQUE", "37", "IFYOUCANREADTHIS", "6377173830041203397265")]
    #[case("ARABESQUE", "89", "ATTACK", "07708081")]
    #[case("SUBWAY", "89", "TOLKIEN", "6819388137")]
    #[case("PORTABLE", "89", "RETRIBUTION", "1721693526840")]
    fn test_straddling_decrypt(#[case] key: &str, #[case] chrs: &str, #[case] pt: &str, #[case] ct: &str) {
        let c = StraddlingCheckerboard::new(key, chrs).unwrap();
        let mut dst = vec![0u8; 100];
        c.decrypt(&mut dst, ct.as_bytes());
        let spt = String::from_utf8_lossy(&dst).trim_matches('\0').to_string();
        assert_eq!(spt, pt);
    }
}
