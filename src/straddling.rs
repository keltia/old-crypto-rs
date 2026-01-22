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

/// Compact encoding entry for a single plaintext byte.
///
/// `len` is 0 for unmapped bytes, or 1/2 for the number of output digits.
/// `bytes` stores the digit bytes for the code.
#[derive(Copy, Clone, Debug, Default)]
struct EncEntry {
    len: u8,
    bytes: [u8; 2],
}

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
            enc_table: [EncEntry::default(); 256],
            dec1: [0; 10],
            dec2: [[0; 10]; 10],
            longc_mask: [false; 10],
        };
        for &c_digit in &c.longc {
            if c_digit.is_ascii_digit() {
                c.longc_mask[(c_digit - b'0') as usize] = true;
            }
        }
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

        let mut i = 0;
        let mut j = 0;
        for &ch in self.full.as_bytes() {
            if freq.contains(&ch) {
                if i < shortc.len() {
                    let digit = shortc[i];
                    self.enc_table[ch as usize] = EncEntry { len: 1, bytes: [digit, 0] };
                    self.dec1[(digit - b'0') as usize] = ch;
                    i += 1;
                }
            } else {
                if j < longc.len() {
                    let bytes = longc[j].as_bytes();
                    if bytes.len() == 2 {
                        let d0 = bytes[0];
                        let d1 = bytes[1];
                        self.enc_table[ch as usize] = EncEntry { len: 2, bytes: [d0, d1] };
                        self.dec2[(d0 - b'0') as usize][(d1 - b'0') as usize] = ch;
                    }
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
        let marker = self.enc_table[b'/' as usize];
        for &ch in src {
            if ch.is_ascii_digit() {
                if marker.len != 0 {
                    dst[offset] = marker.bytes[0];
                    if marker.len == 2 {
                        dst[offset + 1] = marker.bytes[1];
                    }
                    offset += marker.len as usize;

                    dst[offset] = ch;
                    dst[offset + 1] = ch;
                    offset += 2;

                    dst[offset] = marker.bytes[0];
                    if marker.len == 2 {
                        dst[offset + 1] = marker.bytes[1];
                    }
                    offset += marker.len as usize;
                }
            } else {
                let entry = self.enc_table[ch as usize];
                if entry.len != 0 {
                    dst[offset] = entry.bytes[0];
                    if entry.len == 2 {
                        dst[offset + 1] = entry.bytes[1];
                    }
                    offset += entry.len as usize;
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
    use super::*;

    use rstest::rstest;

    #[test]
    fn test_new_cipher() {
        let c = StraddlingCheckerboard::new("ARABESQUE", "89").unwrap();
        assert_eq!(c.full, "ACKVRDLWBFMXEGNYSHOZQIP/UJT-");
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
        let v = c.enc_table[b'V' as usize];
        let k = c.enc_table[b'K' as usize];
        let a = c.enc_table[b'A' as usize];
        let e = c.enc_table[b'E' as usize];
        assert_eq!(v.len, 2);
        assert_eq!(v.bytes, *b"82");
        assert_eq!(k.len, 2);
        assert_eq!(k.bytes, *b"81");
        assert_eq!(a.len, 1);
        assert_eq!(a.bytes[0], b'0');
        assert_eq!(e.len, 1);
        assert_eq!(e.bytes[0], b'2');
        assert_eq!(c.dec2[8][2], b'V');
        assert_eq!(c.dec1[0], b'A');
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
