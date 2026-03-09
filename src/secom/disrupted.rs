//! Subroutines for SECOM cipher implementation.
//!
//! Internal module for the disrupted transposition code.
//!
use crate::Block;
use crate::secom::subr::column_order_from_digits;

/// SECOM's disrupted columnar transposition cipher.
///
/// This cipher implements a variant of columnar transposition where a portion of the grid
/// is intentionally left empty (masked) in a triangular pattern during the first phase
/// of filling, and then filled in a second phase.
///
#[derive(Debug)]
pub(crate) struct SecomDisruptedTransposition {
    /// Width of the transposition grid.
    width: usize,
    /// Column order for reading.
    order: Vec<usize>,
}

impl SecomDisruptedTransposition {
    /// Creates a new `SecomDisruptedTransposition`.
    ///
    pub(crate) fn new(width: usize, key: Vec<u8>) -> Self {
        let order = column_order_from_digits(&key);
        SecomDisruptedTransposition { width, order }
    }

    /// Generates the mask for disrupted transposition.
    ///
    fn disrupted_mask(width: usize, rows: usize, order: &[usize]) -> Vec<bool> {
        let mut mask = vec![false; rows * width];
        let mut tri_idx = 0usize;
        let mut row_offset = 0usize;
        let mut cooldown = 0usize;

        for r in 0..rows {
            let mut start = width;
            if cooldown > 0 {
                cooldown -= 1;
                if cooldown == 0 {
                    tri_idx += 1;
                    row_offset = 0;
                }
            } else if tri_idx < order.len() {
                let sc = order[tri_idx];
                start = sc + row_offset;
                if start < width {
                    row_offset += 1;
                    if sc + row_offset >= width {
                        cooldown = 1; // one full row before next triangle
                    }
                } else {
                    cooldown = 1;
                }
            }

            if start < width {
                let row_off = r * width;
                for c in start..width {
                    mask[row_off + c] = true;
                }
            }
        }
        mask
    }

    /// Performs SECOM's disrupted columnar transposition encryption.
    ///
    fn internal_encrypt(&self, src: &[u8], dst: &mut [u8]) -> usize {
        let width = self.width;
        let rows = (src.len() + width - 1) / width;
        let mask = Self::disrupted_mask(width, rows, &self.order);

        let mut grid = vec![0u8; rows * width];
        let mut idx = 0usize;

        // Filling the transposition:
        //
        // Phase 1: non-triangular
        //
        for r in 0..rows {
            let row_off = r * width;
            for c in 0..width {
                let pos = row_off + c;
                if pos < src.len() && !mask[pos] {
                    grid[pos] = src[idx];
                    idx += 1;
                }
            }
        }
        // Phase 2: triangular
        //
        for r in 0..rows {
            let row_off = r * width;
            for c in 0..width {
                let pos = row_off + c;
                if pos < src.len() && mask[pos] {
                    grid[pos] = src[idx];
                    idx += 1;
                }
            }
        }

        // Get the transformed stream
        //
        let mut out = 0;
        for &col in &self.order {
            for r in 0..rows {
                let pos = r * width + col;
                if pos < src.len() && out < dst.len() {
                    dst[out] = grid[pos];
                    out += 1;
                }
            }
        }
        out
    }

    /// Performs SECOM's disrupted columnar transposition decryption.
    ///
    fn internal_decrypt(&self, src: &[u8], dst: &mut [u8]) -> usize {
        let width = self.width;
        let rows = (src.len() + width - 1) / width;
        let mask = Self::disrupted_mask(width, rows, &self.order);

        // Fill in the columns
        //
        let mut grid = vec![0u8; rows * width];
        let mut idx = 0usize;
        for &col in &self.order {
            for r in 0..rows {
                let pos = r * width + col;
                if pos < src.len() && idx < src.len() {
                    grid[pos] = src[idx];
                    idx += 1;
                }
            }
        }

        let mut out = 0;

        // Read the transposition:
        //
        // Phase 1: non-triangular
        //
        for r in 0..rows {
            let row_off = r * width;
            for c in 0..width {
                let pos = row_off + c;
                if pos < src.len() && !mask[pos] && out < dst.len() {
                    dst[out] = grid[pos];
                    out += 1;
                }
            }
        }

        // Phase 2: triangular
        //
        for r in 0..rows {
            let row_off = r * width;
            for c in 0..width {
                let pos = row_off + c;
                if pos < src.len() && mask[pos] && out < dst.len() {
                    dst[out] = grid[pos];
                    out += 1;
                }
            }
        }

        out
    }
}

impl Block for SecomDisruptedTransposition {
    fn block_size(&self) -> usize {
        self.width
    }

    /// Encrypts source data into destination buffer using disrupted transposition.
    ///
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        self.internal_encrypt(src, dst)
    }

    /// Decrypts source data into destination buffer using disrupted transposition.
    ///
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        self.internal_decrypt(src, dst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secom::subr::{
        column_order_from_digits,
    };

        #[test]
    fn test_disrupted_mask_logic() {
        let key = vec![1, 2, 3]; // simplified
        let order = column_order_from_digits(&key);
        // order for [1, 2, 3] is [0, 1, 2]
        let mask = SecomDisruptedTransposition::disrupted_mask(3, 5, &order);

        // Width 3, Rows 5, order [0, 1, 2]
        // Row 0: start = order[0] + 0 = 0. mask[0..3] = true.
        // row_offset = 1.
        // Row 1: start = 0 + 1 = 1. mask[1..3] = true.
        // row_offset = 2.
        // Row 2: start = 0 + 2 = 2. mask[2..3] = true.
        // row_offset = 3. sc + row_offset >= width (0 + 3 >= 3). cooldown = 1.
        // Row 3: cooldown = 1 -> 0. tri_idx = 1, row_offset = 0. start = 3 (no mask).
        // Row 4: start = order[1] + 0 = 1 + 0 = 1. mask[4*3 + 1..4*3 + 3] = true.
        //
        let expected = vec![
            true, true, true, // Row 0
            false, true, true, // Row 1
            false, false, true, // Row 2
            false, false, false, // Row 3 (cooldown row)
            false, true, true, // Row 4
        ];
        assert_eq!(mask, expected);
    }


}
