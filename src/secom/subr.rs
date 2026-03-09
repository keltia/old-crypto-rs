//! Subroutines for SECOM cipher implementation.
//!

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
pub(crate) fn letters_to_digits_1to0(s: &str) -> Vec<u8> {
    let ranks = crate::helpers::to_numeric(s);
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
pub(crate) fn transposition_widths_from_last_row(row: &[u8]) -> Result<(usize, usize), String> {
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
        return Err("failed to derive transposition widths".to_string());
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
pub(crate) fn vec_to_array_10(v: &[u8]) -> Result<[u8; 10], String> {
    if v.len() != 10 {
        return Err("expected 10 digits".to_string());
    }
    let mut out = [0u8; 10];
    out.copy_from_slice(v);
    Ok(out)
}


