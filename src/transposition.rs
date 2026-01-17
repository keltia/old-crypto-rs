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
}

impl IrregularTransposition {
    /// Creates a new irregular transposition cipher.
    pub fn new(key: &str) -> Result<Self, String> {
        if key.is_empty() {
            return Err("key can not be empty".to_string());
        }
        Ok(IrregularTransposition {
            key: key.to_string(),
            tkey: helpers::to_numeric(key),
        })
    }

    /// Computes which cells are "irregular" (triangular areas) for a given message length.
    fn get_triangular_mask(&self, len: usize) -> Vec<bool> {
        let klen = self.tkey.len();
        let rows = (len + klen - 1) / klen;
        let mut mask = vec![false; rows * klen];

        let mut areas_done = 0;
        for rank in 0..klen {
            if areas_done >= 2 { break; }
            
            let start_col = self.tkey.iter().position(|&x| x == rank as u8).unwrap();
            
            let mut curr_col = start_col;
            let mut curr_row = 0;
            
            while curr_row < rows && curr_col < klen {
                for c in curr_col..klen {
                    mask[curr_row * klen + c] = true;
                }
                curr_row += 1;
                curr_col += 1;
            }
            areas_done += 1;
        }

        mask
    }
}

impl Block for IrregularTransposition {
    fn block_size(&self) -> usize {
        self.tkey.len()
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let klen = self.tkey.len();
        let len = src.len();
        if klen == 0 || len == 0 { return 0; }
        let rows = (len + klen - 1) / klen;
        let mask = self.get_triangular_mask(len);

        let mut grid = vec![0u8; rows * klen];
        let mut active = vec![false; rows * klen];
        let mut src_idx = 0;

        // Phase 1: Fill non-triangular areas row by row
        for r in 0..rows {
            for c in 0..klen {
                let idx = r * klen + c;
                if idx < rows * klen && !mask[idx] && src_idx < len {
                    grid[idx] = src[src_idx];
                    active[idx] = true;
                    src_idx += 1;
                }
            }
        }

        // Phase 2: Fill triangular areas row by row
        for r in 0..rows {
            for c in 0..klen {
                let idx = r * klen + c;
                if idx < rows * klen && mask[idx] && src_idx < len {
                    grid[idx] = src[src_idx];
                    active[idx] = true;
                    src_idx += 1;
                }
            }
        }

        // Read out column by column according to tkey
        let mut dst_idx = 0;
        for i in 0..klen {
            let col = self.tkey.iter().position(|&x| x == i as u8).unwrap();
            for r in 0..rows {
                let idx = r * klen + col;
                if idx < rows * klen && active[idx] {
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
        if klen == 0 || len == 0 { return 0; }
        let rows = (len + klen - 1) / klen;
        let mask = self.get_triangular_mask(len);

        // Determine active cells
        let mut active = vec![false; rows * klen];
        let mut count = 0;
        for r in 0..rows {
            for c in 0..klen {
                let idx = r * klen + c;
                if idx < rows * klen && !mask[idx] && count < len {
                    active[idx] = true;
                    count += 1;
                }
            }
        }
        for r in 0..rows {
            for c in 0..klen {
                let idx = r * klen + c;
                if idx < rows * klen && mask[idx] && count < len {
                    active[idx] = true;
                    count += 1;
                }
            }
        }

        // Fill grid from src column by column
        let mut grid = vec![0u8; rows * klen];
        let mut src_idx = 0;
        for i in 0..klen {
            let col = self.tkey.iter().position(|&x| x == i as u8).unwrap();
            for r in 0..rows {
                let idx = r * klen + col;
                if idx < rows * klen && active[idx] {
                    grid[idx] = src[src_idx];
                    src_idx += 1;
                }
            }
        }

        // Read out row by row, first non-mask then mask
        let mut dst_idx = 0;
        for r in 0..rows {
            for c in 0..klen {
                let idx = r * klen + c;
                if active[idx] && !mask[idx] {
                    dst[dst_idx] = grid[idx];
                    dst_idx += 1;
                }
            }
        }
        for r in 0..rows {
            for c in 0..klen {
                let idx = r * klen + c;
                if active[idx] && mask[idx] {
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
        // Key "94735236270398134" -> klen 17
        // Ranking it:
        // 0: 0 (pos 10)
        // 1: 1 (pos 14)
        // 2: 2 (pos 5)
        // 3: 3 (pos 3)
        // ... and so on.
        // Rank 0 is at pos 10.
        // Rank 1 is at pos 14.
        
        let key = "94735236270398134";
        let c = IrregularTransposition::new(key).unwrap();
        let mask = c.get_triangular_mask(150);
        let klen = 17;
        
        // Row 0:
        // rank 0 is at col 10. So col 10..17 should be true in row 0.
        // rank 1 is at col 14. Wait, the description says:
        // "The first triangular area starts at the top of the column which will be read out first, and extends to the end of the first row."
        // First to be read out is rank 0.
        // Second to be read out is rank 1.
        
        // Rank 0 is at pos 10.
        // Rank 1 is at pos 14.
        
        // Row 0: col 10 to 16 are true.
        for col in 10..17 {
            assert!(mask[0 * klen + col], "Row 0 col {} should be true", col);
        }
        for col in 0..10 {
            assert!(!mask[0 * klen + col], "Row 0 col {} should be false", col);
        }
        
        // Row 1: col 11 to 16 are true. (starts one column later)
        for col in 11..17 {
            assert!(mask[1 * klen + col], "Row 1 col {} should be true", col);
        }
        assert!(!mask[1 * klen + 10]);

        // Second triangular area starts at rank 1 column (pos 14)
        // Row 0: col 14 to 16 are true. (already set by first area)
        // Wait, "Then, after one space, the second triangular area starts"
        // Row 0: rank 1 is at pos 14. It starts there.
        assert!(mask[0 * klen + 14]);
    }
}
