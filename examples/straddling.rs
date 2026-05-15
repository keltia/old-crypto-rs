use eyre::Result;

use old_crypto_rs::Block;
use old_crypto_rs::helpers::{English, Frequent, shuffle, Alphabet, LatinSC};

use std::marker::PhantomData;

/// Compact encoding entry for a single plaintext byte.
///
/// `len` is 0 for unmapped bytes, or 1/2 for the number of output digits.
/// `bytes` stores the digit bytes for the code.
#[derive(Copy, Clone, Default)]
struct EncEntry {
    len: u8,
    bytes: [u8; 2],
}

impl std::fmt::Debug for EncEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b0 = if self.bytes[0] == 0 {
            b'.'
        } else {
            self.bytes[0]
        };
        let b1 = if self.bytes[1] == 0 {
            b'.'
        } else {
            self.bytes[1]
        };
        let code = [b0, b1];
        f.write_str(std::str::from_utf8(&code).unwrap_or(".."))
    }
}

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
struct Straddling<A: Alphabet, F: Frequent> {
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
    /// The frequent letters.
    _marker: PhantomData<(A,F)>,
}

impl<A: Alphabet, F: Frequent> std::fmt::Display for Straddling<A, F> {
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

impl<A: Alphabet, F: Frequent> Straddling<A, F> {
    pub fn new(key: &str, chrs: &str) -> Result<Self> {
        // Default alphabet.
        //
        let alphabet = match String::from_utf8(A::ALPHABET.to_vec()) {
            Ok(a) => a,
            Err(e) => return Err(Error::InvalidAlphabet.into()),
        };
        if key.is_empty() {
            return Err(Error::EmptyKeys.into());
        }
        if chrs.len() < 2 {
            return Err(Error::TooShort(chrs.len(), 2).into());
        }

        let longc = vec![chrs.as_bytes()[0], chrs.as_bytes()[1]];

        // Shake the alphabet a bit
        //
        let full = shuffle(key, &alphabet);
        dbg!(&full);
        let shortc = Self::extract(ALL_CIPHER, &longc);
        dbg!(&shortc);

        let mut c = Straddling {
            key: key.to_string(),
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
        dbg!(&longc);

        let mut i = 0;
        let mut j = 0;
        for &ch in self.full.as_bytes() {
            if freq.contains(&ch) {
                if i < shortc.len() {
                    let digit = shortc[i];
                    self.enc_table[ch as usize] = EncEntry {
                        len: 1,
                        bytes: [digit, 0],
                    };
                    self.dec1[(digit - b'0') as usize] = ch;
                    i += 1;
                }
            } else {
                if j < longc.len() {
                    let bytes = longc[j].as_bytes();
                    if bytes.len() == 2 {
                        let d0 = bytes[0];
                        let d1 = bytes[1];
                        self.enc_table[ch as usize] = EncEntry {
                            len: 2,
                            bytes: [d0, d1],
                        };
                        self.dec2[(d0 - b'0') as usize][(d1 - b'0') as usize] = ch;
                    }
                    j += 1;
                }
            }
        }
    }
}

const KEY: &str = "ARABESQUE";
const PT1: &str = "ATTACKAT2AM";
const PT2: &str = "IFYOUCANREADTHIS";

fn main() -> Result<()> {
    let cipher = Straddling::<LatinSC, English>::new(KEY, "89")?;
    println!("{}", cipher);

    let mut encrypted = vec![0u8; 100];
    let len = cipher.encrypt(&mut encrypted, PT1.as_bytes());
    encrypted.truncate(len);
    println!("{}", std::str::from_utf8(&encrypted)?);

    let cipher = Straddling::<LatinSC, English>::new(KEY, "37")?;
    println!("{}", cipher);

    let mut encrypted = vec![0u8; 100];
    let len = cipher.encrypt(&mut encrypted, PT2.as_bytes());
    encrypted.truncate(len);
    println!("{}", std::str::from_utf8(&encrypted)?);

    Ok(())
}

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to derive transposition widths")]
    BadDerivationKey,
    #[error("failed to derive keys")]
    BadKeyStream,
    #[error("checkerboard symbols exhausted")]
    CheckerboardExhausted,
    #[error("{0} digits expected")]
    DigitsExpected(usize),
    #[error("Empty input")]
    EmptyInput,
    #[error("Keys must be not be empty")]
    EmptyKeys,
    #[error("Incompatible variants, like 5x5 but Latin36.")]
    IncompatibleVariants,
    #[error("Invalid alphabet")]
    InvalidAlphabet,
    #[error("Key must be at least {0} characters long")]
    KeyTooShort(usize),
    #[error("Alphabet must be {0} characters long")]
    AlphabetTooShort(usize),
    #[error("Every input must have the same length: {0} vs {1}")]
    LengthMismatch(usize, usize),
    #[error("Input {0} must be at least {1} characters long")]
    TooShort(usize, usize),
    #[error("Failed to generate rows")]
    RowGenerationFailed,
}

pub type EnglishStraddling = Straddling<LatinSC, English>;

impl<A: Alphabet, F: Frequent> Block for Straddling<A, F> {
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
