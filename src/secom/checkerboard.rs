//! Subroutines for SECOM cipher implementation.
//!
//! Internal module for the SECOM straddling checkerboard
//!
use crate::Block;

const FREQ_BLANK_POS: [usize; 3] = [2, 5, 8]; // 3rd, 6th, 9th positions

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
        let base_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ*0123456789";
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

