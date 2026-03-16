//! Subroutines for SECOM cipher implementation.
//!
//! Internal module for the SECOM straddling checkerboard
//!
use crate::Block;

const FREQ_BLANK_POS: [usize; 3] = [2, 5, 8]; // 3rd, 6th, 9th positions

/// Our alphabet includes digits and 3 more caracters, because we have 3 digits.
const BASE_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ*0123456789/+";

/// Internal encoding entry for a single character in the checkerboard.
///
#[derive(Copy, Clone, Debug, Default)]
struct EncEntry {
    /// Number of digits used for encoding (1 or 2).
    len: u8,
    /// The digit bytes (ASCII characters '0'-'9').
    bytes: [u8; 2],
}

/// A SECOM-variant straddling checkerboard.
///
/// It uses a 10-digit header to map characters to 1-digit or 2-digit codes.
/// It always has 3 "long" digits that prefix two-digit codes.
///
#[derive(Debug)]
pub(crate) struct SecomCheckerboard {
    /// The three digits that prefix two-digit codes.
    pub(crate) longc: [u8; 3],
    /// Fast encoding table indexed by plaintext byte.
    enc: [EncEntry; 256],
    /// Fast decoding table for single-digit codes.
    dec1: [u8; 10],
    /// Fast decoding table for two-digit codes.
    dec2: [[u8; 10]; 10],
}

impl SecomCheckerboard {
    /// Creates a new SECOM checkerboard.
    ///
    /// # Arguments
    ///
    /// * `header` - A 10-digit permutation used to define the layout.
    /// * `freq` - A string of 7 frequent characters that will get single-digit codes.
    ///
    pub(crate) fn new(header: [u8; 10], freq: &str) -> Result<Self, String> {
        let mut longc = [0u8; 3];
        for (i, &pos) in FREQ_BLANK_POS.iter().enumerate() {
            longc[i] = header[pos];
        }

        let mut enc = [EncEntry::default(); 256];
        let mut dec1 = [0u8; 10];
        let mut dec2 = [[0u8; 10]; 10];

        // Place frequent letters on the top row.
        //
        let mut freq_iter = freq.as_bytes().iter();
        for col in 0..10 {
            if FREQ_BLANK_POS.contains(&col) {
                continue;
            }
            if let Some(&ch) = freq_iter.next() {
                let digit = header[col];
                enc[ch as usize] = EncEntry { len: 1, bytes: [b'0' + digit, 0] };
                dec1[digit as usize] = ch;
            }
        }

        // Prepare header digit -> column mapping.
        //
        let mut col_for_digit = [0usize; 10];
        for (col, &d) in header.iter().enumerate() {
            col_for_digit[d as usize] = col;
        }

        // Derive symbols for the extra rows by removing characters in `freq` from the alphabet.
        // The SECOM alphabet consists of A-Z, 0-9, and '*' for space.
        //
        let base_alphabet = BASE_ALPHABET;
        let mut checker_extra = String::with_capacity(30);
        for c in base_alphabet.chars() {
            if !freq.contains(c) {
                checker_extra.push(c);
            }
        }

        // Fill the three rows under long digits, starting at their column.
        //
        let mut symbols = checker_extra.as_bytes().iter();
        for &row_digit in &longc {
            let start_col = if row_digit == 2 { 0 } else { col_for_digit[row_digit as usize] };
            for i in 0..10 {
                let col = (start_col + i) % 10;
                let ch = *symbols.next().ok_or("checkerboard symbols exhausted")?;
                let d1 = header[col];
                enc[ch as usize] = EncEntry { len: 2, bytes: [b'0' + row_digit, b'0' + d1] };
                dec2[row_digit as usize][d1 as usize] = ch;
            }
        }

        Ok(SecomCheckerboard {
            longc,
            enc,
            dec1,
            dec2,
        })
    }
}

impl Block for SecomCheckerboard {
    fn block_size(&self) -> usize {
        1
    }

    /// Encrypts plaintext bytes into a sequence of digit bytes.
    ///
    /// # Arguments
    ///
    /// * `dst` - The destination buffer for the encoded digits.
    /// * `src` - The source plaintext bytes.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to `dst`.
    ///
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let mut out = 0;
        for &ch in src {
            let entry = self.enc[ch as usize];
            if entry.len == 0 {
                continue;
            }
            if out + entry.len as usize > dst.len() {
                break;
            }
            dst[out] = entry.bytes[0];
            if entry.len == 2 {
                dst[out + 1] = entry.bytes[1];
            }
            out += entry.len as usize;
        }
        out
    }

    /// Decrypts digit bytes back into plaintext bytes.
    ///
    /// # Arguments
    ///
    /// * `dst` - The destination buffer for the decrypted plaintext.
    /// * `src` - The source digit bytes to decode.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to `dst`.
    ///
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let mut out = 0;
        let mut i = 0;
        while i < src.len() {
            let ch = src[i];
            if !ch.is_ascii_digit() {
                i += 1;
                continue;
            }
            let d0 = (ch - b'0') as usize;
            if self.longc.contains(&(d0 as u8)) {
                if i + 1 >= src.len() {
                    break;
                }
                let ch1 = src[i + 1];
                if !ch1.is_ascii_digit() {
                    i += 2;
                    continue;
                }
                let d1 = (ch1 - b'0') as usize;
                let ptc = self.dec2[d0][d1];
                if ptc != 0 && out < dst.len() {
                    dst[out] = ptc;
                    out += 1;
                }
                i += 2;
            } else {
                let ptc = self.dec1[d0];
                if ptc != 0 && out < dst.len() {
                    dst[out] = ptc;
                    out += 1;
                }
                i += 1;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkerboard_layout() {
        let header = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let freq = "ATONESI";
        let cb = SecomCheckerboard::new(header, freq).unwrap();
        
        // FREQ_BLANK_POS = [2, 5, 8]
        // header[2]=2, header[5]=5, header[8]=8 should be long digits
        assert_eq!(cb.longc, [2, 5, 8]);

        // ATONESI should be single digits
        // cols 0, 1, 3, 4, 6, 7, 9
        // header[0]=0 -> A
        // header[1]=1 -> T
        // header[3]=3 -> O
        // header[4]=4 -> N
        // header[6]=6 -> E
        // header[7]=7 -> S
        // header[9]=9 -> I

        let mut dst = [0u8; 10];
        let n = cb.encrypt(&mut dst, b"ATONESI");
        assert_eq!(n, 7);
        assert_eq!(&dst[..7], b"0134679");

        let mut pt = [0u8; 10];
        let n = cb.decrypt(&mut pt, b"0134679");
        assert_eq!(n, 7);
        assert_eq!(&pt[..7], b"ATONESI");
    }

    #[test]
    fn test_checkerboard_two_digits() {
        let header = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let freq = "ATONESI";
        let cb = SecomCheckerboard::new(header, freq).unwrap();

        // Let's test some characters that should be 2 digits.
        // Alphabet: ABCDEFGHIJKLMNOPQRSTUVWXYZ*0123456789
        // A, T, O, N, E, S, I are freq.
        // Others: B, C, D, F, G, H, J, K, L, M, P, Q, R, U, V, W, X, Y, Z, *, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
        // Row 1 starts with long digit cb.longc[0] = 2.
        // It should start at col_for_digit[2] = 2.
        // header[2]=2, header[3]=3, ...
        // So 'B' should be "22" (if header[2]=2 is used as 2nd digit)
        // Actually, code says:
        // let start_col = if row_digit == 2 { 0 } else { col_for_digit[row_digit as usize] };
        // row_digit is 2, so start_col = 0.
        // for i in 0..10 { col = (0 + i) % 10; d1 = header[col]; enc['B'] = [2, d1] ... }
        // 'B' is 1st in symbols, so it gets col 0, d1 = header[0] = 0.
        // So 'B' -> "20".
        
        let mut dst = [0u8; 10];
        let n = cb.encrypt(&mut dst, b"B");
        assert_eq!(n, 2);
        assert_eq!(&dst[..2], b"20");

        let mut pt = [0u8; 10];
        let n = cb.decrypt(&mut pt, b"20");
        assert_eq!(n, 1);
        assert_eq!(&pt[..1], b"B");
    }

    #[test]
    fn test_buffer_too_small() {
        let header = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let cb = SecomCheckerboard::new(header, "ATONESI").unwrap();
        let mut dst = [0u8; 3];
        // "ATONESI" -> 7 digits.
        let n = cb.encrypt(&mut dst, b"ATONESI");
        assert_eq!(n, 3);
        assert_eq!(&dst[..3], b"013");
    }

    #[test]
    fn test_invalid_chars() {
        let header = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let cb = SecomCheckerboard::new(header, "ATONESI").unwrap();
        let mut dst = [0u8; 10];
        // '#' is not in alphabet, should be skipped
        let n = cb.encrypt(&mut dst, b"A#T");
        assert_eq!(n, 2);
        assert_eq!(&dst[..2], b"01");
        
        let mut pt = [0u8; 10];
        // 'a' is not a digit, should be skipped in decrypt
        let n = cb.decrypt(&mut pt, b"0a1");
        assert_eq!(n, 2);
        assert_eq!(&pt[..2], b"AT");
    }
}

