//! Transposition cipher implementation.
//!
//! This module implements a columnar transposition cipher, which rearranges the plaintext
//! by writing it in rows of a fixed length (determined by the key), then reading out the
//! columns in an order determined by the alphabetical order of the key letters.
//!
//! # Examples
//!
//! ```
//! use old_crypto_rs::{Block, Transposition};
//!
//! let cipher = Transposition::new("ZEBRAS").unwrap();
//! let plaintext = b"WEAREDISCOVEREDFLEEATONCE";
//! let mut ciphertext = vec![0u8; plaintext.len()];
//! cipher.encrypt(&mut ciphertext, plaintext);
//! ```
//!
use crate::Block;
use crate::helpers;

/// A columnar transposition cipher.
#[derive(Debug)]
pub struct Transposition {
    #[allow(dead_code)]
    key: String,
    tkey: Vec<u8>,
}

impl Transposition {
    /// Creates a new regular columnar transposition cipher.
    pub fn new(key: &str) -> Result<Self, String> {
        if key.is_empty() {
            return Err("key can not be empty".to_string());
        }
        Ok(Transposition {
            key: key.to_string(),
            tkey: helpers::to_numeric(key),
        })
    }
}

impl Block for Transposition {
    fn block_size(&self) -> usize {
        self.tkey.len()
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let klen = self.tkey.len();
        let mut offset = 0;
        for i in 0..klen {
            let j = self.tkey.iter().position(|&x| x == i as u8).unwrap();
            let mut curr = j;
            while curr < src.len() {
                dst[offset] = src[curr];
                offset += 1;
                curr += klen;
            }
        }
        src.len()
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let klen = self.tkey.len();
        if klen == 0 || src.is_empty() {
            return 0;
        }

        let scol = src.len() / klen;
        let extra = src.len() % klen;

        let mut current = 0;
        for j in 0..klen {
            let ind = self.tkey.iter().position(|&x| x == j as u8).unwrap();
            let how_many = if ind < extra { scol + 1 } else { scol };

            let mut dst_idx = ind;
            for k in 0..how_many {
                dst[dst_idx] = src[current + k];
                dst_idx += klen;
            }
            current += how_many;
        }
        src.len()
    }
}

/// An irregular transposition cipher used in the VIC cipher.
#[derive(Debug)]
pub struct IrregularTransposition {
    #[allow(dead_code)]
    key: String,
    tkey: Vec<u8>,
    rank_pos: [usize; 2],
    tkey_order: Vec<usize>,
}

impl IrregularTransposition {
    /// Creates a new irregular transposition cipher.
    pub fn new(key: &str) -> Result<Self, String> {
        if key.is_empty() {
            return Err("key can not be empty".to_string());
        }
        let tkey = helpers::to_numeric(key);
        let pos0 = tkey.iter().position(|&x| x == 0).unwrap();
        let pos1 = tkey.iter().position(|&x| x == 1).unwrap();
        
        let klen = tkey.len();
        let mut tkey_order = vec![0; klen];
        for i in 0..klen {
            tkey_order[i] = tkey.iter().position(|&x| x == i as u8).unwrap();
        }

        Ok(IrregularTransposition {
            key: key.to_string(),
            tkey,
            rank_pos: [pos0, pos1],
            tkey_order,
        })
    }

    /// Computes which cells are "irregular" (triangular areas) for a given message length.
    #[inline]
    fn is_in_triangular_area(&self, r: usize, c: usize) -> bool {
        // The triangle starts at (row 0, start_col)
        // It expands to the right: at row `i`, it covers columns `start_col + i` to `klen - 1`
        (c >= self.rank_pos[0] + r || c >= self.rank_pos[1] + r) && c < self.tkey.len()
    }
}

impl Block for IrregularTransposition {
    fn block_size(&self) -> usize {
        self.tkey.len()
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let klen = self.tkey.len();
        let len = src.len();
        if klen == 0 || len == 0 {
            return 0;
        }
        let rows = (len + klen - 1) / klen;

        let mut grid = vec![0u8; rows * klen];
        let mut active = vec![0u8; (rows * klen + 7) / 8];
        let mut src_idx = 0;

        // Phase 1: Fill non-triangular areas row by row
        for r in 0..rows {
            let row_off = r * klen;
            for c in 0..klen {
                if !self.is_in_triangular_area(r, c) && src_idx < len {
                    let idx = row_off + c;
                    grid[idx] = src[src_idx];
                    active[idx >> 3] |= 1 << (idx & 7);
                    src_idx += 1;
                }
            }
        }

        // Phase 2: Fill triangular areas row by row
        for r in 0..rows {
            let row_off = r * klen;
            for c in 0..klen {
                if self.is_in_triangular_area(r, c) && src_idx < len {
                    let idx = row_off + c;
                    grid[idx] = src[src_idx];
                    active[idx >> 3] |= 1 << (idx & 7);
                    src_idx += 1;
                }
            }
        }

        // Read out column by column according to tkey
        let mut dst_idx = 0;
        for &col in &self.tkey_order {
            for r in 0..rows {
                let idx = r * klen + col;
                if (active[idx >> 3] & (1 << (idx & 7))) != 0 {
                    dst[dst_idx] = grid[idx];
                    dst_idx += 1;
                }
            }
        }

        len
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let klen = self.tkey.len();
        let len = src.len();
        if klen == 0 || len == 0 {
            return 0;
        }
        let rows = (len + klen - 1) / klen;

        // Determine active cells
        let mut active = vec![0u8; (rows * klen + 7) / 8];
        let mut count = 0;
        for r in 0..rows {
            let row_off = r * klen;
            for c in 0..klen {
                if !self.is_in_triangular_area(r, c) && count < len {
                    let idx = row_off + c;
                    active[idx >> 3] |= 1 << (idx & 7);
                    count += 1;
                }
            }
        }
        for r in 0..rows {
            let row_off = r * klen;
            for c in 0..klen {
                if self.is_in_triangular_area(r, c) && count < len {
                    let idx = row_off + c;
                    active[idx >> 3] |= 1 << (idx & 7);
                    count += 1;
                }
            }
        }

        // Fill grid from src column by column
        let mut grid = vec![0u8; rows * klen];
        let mut src_idx = 0;
        for &col in &self.tkey_order {
            for r in 0..rows {
                let idx = r * klen + col;
                if (active[idx >> 3] & (1 << (idx & 7))) != 0 {
                    grid[idx] = src[src_idx];
                    src_idx += 1;
                }
            }
        }

        // Read out row by row, first non-mask then mask
        let mut dst_idx = 0;
        for r in 0..rows {
            let row_off = r * klen;
            for c in 0..klen {
                let idx = row_off + c;
                if ((active[idx >> 3] & (1 << (idx & 7))) != 0) && !self.is_in_triangular_area(r, c) {
                    dst[dst_idx] = grid[idx];
                    dst_idx += 1;
                }
            }
        }
        for r in 0..rows {
            let row_off = r * klen;
            for c in 0..klen {
                let idx = row_off + c;
                if ((active[idx >> 3] & (1 << (idx & 7))) != 0) && self.is_in_triangular_area(r, c) {
                    dst[dst_idx] = grid[idx];
                    dst_idx += 1;
                }
            }
        }

        len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    #[test]
    fn test_new_cipher() {
        let c = Transposition::new("ABCDE").unwrap();
        assert_eq!(c.key, "ABCDE");
        assert_eq!(c.tkey, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn test_new_cipher_empty() {
        let c = Transposition::new("");
        assert!(c.is_err());
    }

    #[test]
    fn test_transposition_block_size() {
        let c = Transposition::new("ABCDE").unwrap();
        assert_eq!(c.block_size(), 5);
    }

    #[rstest]
    #[case("ARABESQUE", "AATNIITN2MIHAAXOOTCT2RNXDNENNAOXMB2TW4DTGKP3ES1TISUY3", "ATTACKATDAWNATPOINT42X23XSENDMOREMUNITIONSBYNIGHTX123")]
    #[case("SUBWAY", "CWI2DUNG3TDP2EEIN1AAATXOIBTTTT4SRTYXAAOXNMOI2KNN3MNSH", "ATTACKATDAWNATPOINT42X23XSENDMOREMUNITIONSBYNIGHTX123")]
    #[case("PORTABLE", "CA2DIN3KTXMTITO3ROHAP2OIGTANSMSXADIXENTTWTEUB1AN4NNY2", "ATTACKATDAWNATPOINT42X23XSENDMOREMUNITIONSBYNIGHTX123")]
    #[case("SUBWAY", "AFDFADAGAAAAVVVVGFGVGGGX", "AVAGAGAVDFFGAVAGDGAVGVFX")]
    fn test_transposition_encrypt(#[case] key: &str, #[case] ct: &str, #[case] pt: &str) {
        let c = Transposition::new(key).unwrap();
        let mut dst = vec![0u8; pt.len()];
        c.encrypt(&mut dst, pt.as_bytes());
        assert_eq!(String::from_utf8(dst).unwrap(), ct);
    }

    #[rstest]
    #[case("ARABESQUE", "AATNIITN2MIHAAXOOTCT2RNXDNENNAOXMB2TW4DTGKP3ES1TISUY3", "ATTACKATDAWNATPOINT42X23XSENDMOREMUNITIONSBYNIGHTX123")]
    #[case("SUBWAY", "CWI2DUNG3TDP2EEIN1AAATXOIBTTTT4SRTYXAAOXNMOI2KNN3MNSH", "ATTACKATDAWNATPOINT42X23XSENDMOREMUNITIONSBYNIGHTX123")]
    #[case("PORTABLE", "CA2DIN3KTXMTITO3ROHAP2OIGTANSMSXADIXENTTWTEUB1AN4NNY2", "ATTACKATDAWNATPOINT42X23XSENDMOREMUNITIONSBYNIGHTX123")]
    #[case("SUBWAY", "AFDFADAGAAAAVVVVGFGVGGGX", "AVAGAGAVDFFGAVAGDGAVGVFX")]
    fn test_transposition_decrypt(#[case] key: &str, #[case] ct: &str, #[case] pt: &str) {
        let c = Transposition::new(key).unwrap();
        let mut dst = vec![0u8; pt.len()];
        c.decrypt(&mut dst, ct.as_bytes());
        assert_eq!(String::from_utf8(dst).unwrap(), pt);
    }

    #[test]
    fn test_irregular_transposition_mask() {
        let key = "94735236270398134";
        let c = IrregularTransposition::new(key).unwrap();

        // Row 0:
        // Rank 0 is at pos 10.
        // Rank 1 is at pos 14.
        for col in 10..17 {
            assert!(c.is_in_triangular_area(0, col), "Row 0 col {} should be true", col);
        }
        for col in 0..10 {
            assert!(!c.is_in_triangular_area(0, col), "Row 0 col {} should be false", col);
        }

        // Row 1: col 11 to 16 are true for the first triangle.
        for col in 11..17 {
            assert!(c.is_in_triangular_area(1, col), "Row 1 col {} should be true", col);
        }
        assert!(!c.is_in_triangular_area(1, 10));

        // Row 0: rank 1 is at pos 14.
        assert!(c.is_in_triangular_area(0, 14));
    }
}
