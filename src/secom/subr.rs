//! Subroutines for SECOM cipher implementation.
//!

use crate::helpers::to_numeric;

use eyre::{eyre, Result};

/// Normalizes the key phrase by keeping only ASCII alphabetic characters and
/// converting them to uppercase.
///
pub(crate) fn normalize_key_phrase(key_phrase: &str) -> String {
    key_phrase
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Converts each letter of the string into a digit from 1 to 0 based on its
/// alphabetical rank (1 for the earliest letter, 0 for the 10th).
///
/// NOTE: this can in theory calculate for any length, but we only use it 10 letters
/// at a time to conform to SECOM specs.
///
pub(crate) fn letters_to_digits_1to0(s: &str) -> Vec<u8> {
    let ranks = to_numeric(s);
    ranks.into_iter().map(|x| (x + 1) % 10).collect()
}

/// Performs digit-wise addition modulo 10 for two slices.
///
pub(crate) fn addmod10(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| (x + y) % 10).collect()
}

/// Generates a new row by adding adjacent digits modulo 10 (Fibonacci-style).
///
pub(crate) fn chain_add_row(row: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(row.len());
    if row.len() < 2 {
        return out;
    }
    let mut a = row[0];
    let mut b = row[1];
    out.push((a + b) % 10);
    for i in 2..row.len() {
        a = b;
        b = row[i];
        out.push((a + b) % 10);
    }
    // Now we need to continue adding the newly generated digits
    //
    let mut i = 0;
    while out.len() < row.len() {
        a = b;
        b = out[i];
        out.push((a + b) % 10);
        i += 1;
    }
    out
}

/// Ranks digits from 1 to 0 (1 for smallest, 0 for 10th).
///
pub(crate) fn rank_digits_1to0(digits: &[u8]) -> Vec<u8> {
    let mut indexed: Vec<(usize, u8)> = digits.iter().enumerate().map(|(i, &d)| (i, d)).collect();
    indexed.sort_by_key(|&(i, d)| (if d == 0 { 10 } else { d }, i));
    let mut out = vec![0u8; digits.len()];
    for (rank, (idx, _)) in indexed.into_iter().enumerate() {
        out[idx] = ((rank + 1) % 10) as u8;
    }
    out
}

/// Derives two transposition widths from the last row of the key expansion.
///
pub(crate) fn transposition_widths_from_last_row(row: &[u8]) -> Result<(usize, usize)> {
    let mut used = [false; 10];
    let mut w1 = 0usize;
    let mut w2 = 0usize;
    let mut sum = 0usize;
    let mut phase = 0;

    for &d in row.iter().rev() {
        let idx = d as usize;
        if used[idx] {
            continue;
        }
        used[idx] = true;
        sum += idx;
        if sum > 9 {
            if phase == 0 {
                w1 = sum;
                sum = 0;
                phase = 1;
            } else {
                w2 = sum;
                break;
            }
        }
    }
    if w1 == 0 || w2 == 0 {
        return Err(eyre!("failed to derive transposition widths").into());
    }
    Ok((w1, w2))
}

/// Derives a column reading order from a digit key.
///
pub(crate) fn column_order_from_digits(key: &[u8]) -> Vec<usize> {
    let mut indexed: Vec<(usize, u8)> = key.iter().enumerate().map(|(i, &d)| (i, d)).collect();
    indexed.sort_by_key(|&(i, d)| (if d == 0 { 10 } else { d }, i));
    indexed.into_iter().map(|(i, _)| i).collect()
}

/// Reads out columns from the 5x10 grid in the specified order.
///
pub(crate) fn read_out_columns(rows: &[Vec<u8>], key10: &[u8]) -> Vec<u8> {
    let order = column_order_from_digits(key10);
    let mut out = Vec::with_capacity(rows.len() * 10);
    for &col in &order {
        for r in rows {
            out.push(r[col]);
        }
    }
    out
}

/// Converts a slice to a fixed-size array of 10 bytes.
///
pub(crate) fn vec_to_array_10(v: &[u8]) -> Result<[u8; 10]> {
    if v.len() != 10 {
        return Err(eyre!("expected 10 digits").into());
    }
    let mut out = [0u8; 10];
    out.copy_from_slice(v);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_key_phrase() {
        assert_eq!(normalize_key_phrase("I Dream Of Jeannie With T"), "IDREAMOFJEANNIEWITHT");
        assert_eq!(normalize_key_phrase("hello-world! 123"), "HELLOWORLD");
        assert_eq!(normalize_key_phrase(""), "");
    }

    #[test]
    fn test_letters_to_digits_1to0() {
        let res = letters_to_digits_1to0("MAKENEWFRI");
        assert_eq!(res, vec![7, 1, 6, 2, 8, 3, 0, 4, 9, 5, ]);

        let res = letters_to_digits_1to0("ENDSBUTKEE");
        assert_eq!(res, vec![3, 7, 2, 8, 1, 0, 9, 6, 4, 5]);

        let res = letters_to_digits_1to0("IDREAMOFJE");
        assert_eq!(res, vec![6, 2, 0, 3, 1, 8, 9, 5, 7, 4]);

        let res = letters_to_digits_1to0("ANNIEWITHT");
        assert_eq!(res, vec![1, 6, 7, 4, 2, 0, 5, 8, 3, 9]);
    }

    #[test]
    fn test_addmod10() {
        let a = vec![1, 2, 3, 9];
        let b = vec![5, 8, 2, 1];
        assert_eq!(addmod10(&a, &b), vec![6, 0, 5, 0]);

        // different lengths
        //
        let c = vec![1, 2];
        let d = vec![3, 4, 5];
        assert_eq!(addmod10(&c, &d), vec![4, 6]);
    }

    #[test]
    fn test_chain_add_row() {
        let row = vec![1, 2, 3];
        // 1+2=3, 2+3=5, 3+3=6
        // Result should be [3, 5, 6]
        //
        assert_eq!(chain_add_row(&row), vec![3, 5, 6]);

        let row2 = vec![1, 2, 3, 4, 5];
        // 1+2=3, 2+3=5, 3+4=7, 4+5=9, 5+3=8
        // Result should be [3, 5, 7, 9, 8]
        //
        assert_eq!(chain_add_row(&row2), vec![3, 5, 7, 9, 8]);
    }

    #[test]
    fn test_rank_digits_1to0() {
        // digits: 1, 2, 3, 0
        // 1 -> rank 0 -> 1
        // 2 -> rank 1 -> 2
        // 3 -> rank 2 -> 3
        // 0 -> rank 3 -> 4
        // Wait, 0 is treated as 10.
        // 1, 2, 3, 0 -> ranks are 0, 1, 2, 3. (rank+1)%10 -> 1, 2, 3, 4
        //
        assert_eq!(rank_digits_1to0(&[1, 2, 3, 0]), vec![1, 2, 3, 4]);
        
        // 0, 9, 1
        // sorted: 1, 9, 0
        // 1 is rank 0 -> 1
        // 9 is rank 1 -> 2
        // 0 is rank 2 -> 3
        //
        assert_eq!(rank_digits_1to0(&[0, 9, 1]), vec![3, 2, 1]);

        // Duplicate digits
        // 2, 1, 2
        // sorted: 1(idx 1), 2(idx 0), 2(idx 2)
        // 1(idx 1) -> rank 0 -> 1
        // 2(idx 0) -> rank 1 -> 2
        // 2(idx 2) -> rank 2 -> 3
        //
        assert_eq!(rank_digits_1to0(&[2, 1, 2]), vec![2, 1, 3]);
    }

    #[test]
    fn test_transposition_widths_from_last_row() {
        // row: 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
        // rev: 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
        // sum starts 0, 1, 2, 3, 4, 5. sum=15 (>9). w1=15.
        // next 6, 7. sum=13 (>9). w2=13.
        // Wait, I got (10, 11) in failure. Why?
        // rev: 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
        // d=0: sum=0. used[0]=true.
        // d=1: sum=1. used[1]=true.
        // d=2: sum=3. used[2]=true.
        // d=3: sum=6. used[3]=true.
        // d=4: sum=10 (>9). w1=10. sum=0. phase=1. used[4]=true.
        // d=5: sum=5. used[5]=true.
        // d=6: sum=11 (>9). w2=11. break. used[6]=true.
        // Result (10, 11).
        //
        let row = vec![9, 8, 7, 6, 5, 4, 3, 2, 1, 0];
        assert_eq!(transposition_widths_from_last_row(&row).unwrap(), (10, 11));

        let row2 = vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
        // rev: 1, 1, ...
        // used[1] becomes true, all others ignored.
        // sum=1 forever. Error.
        //
        assert!(transposition_widths_from_last_row(&row2).is_err());
    }

    #[test]
    fn test_column_order_from_digits() {
        assert_eq!(column_order_from_digits(&[3, 1, 2]), vec![1, 2, 0]);
        assert_eq!(column_order_from_digits(&[0, 1, 2]), vec![1, 2, 0]); // 0 is 10
    }

    #[test]
    fn test_read_out_columns() {
        let rows = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
        ];
        // key [3, 1, 2] -> order [1, 2, 0]
        // col 1: 2, 5
        // col 2: 3, 6
        // col 0: 1, 4
        // out: 2, 5, 3, 6, 1, 4
        //
        assert_eq!(read_out_columns(&rows, &[3, 1, 2]), vec![2, 5, 3, 6, 1, 4]);
    }

    #[test]
    fn test_vec_to_array_10() {
        let v = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        assert_eq!(vec_to_array_10(&v).unwrap(), [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert!(vec_to_array_10(&[1, 2]).is_err());
    }
}


