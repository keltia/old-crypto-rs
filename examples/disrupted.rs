//! Example demonstrating the generic Disrupted transposition cipher.
//!
//! This example shows how to use the Disrupted transposition cipher with different
//! masking policies (NoMask, VIC-style, and SECOM-style).

use old_crypto_rs::{Block, Disrupted, Transposition};
use old_crypto_rs::helpers::TranspositionMask;

/// A simple no-mask policy (behaves like regular transposition).
struct NoMask;
impl TranspositionMask for NoMask {
    fn mask(_width: usize, rows: usize, _order: &[usize]) -> Vec<bool> {
        vec![false; _width * rows]
    }
}

/// VIC-style triangular mask policy.
struct VicMask;
impl TranspositionMask for VicMask {
    fn mask(width: usize, rows: usize, order: &[usize]) -> Vec<bool> {
        let mut mask = vec![false; width * rows];
        let pos0 = order[0];
        let pos1 = order[1];

        for r in 0..rows {
            let row_off = r * width;
            for c in 0..width {
                if (c >= pos0 + r || c >= pos1 + r) && c < width {
                    mask[row_off + c] = true;
                }
            }
        }
        mask
    }
}

/// SECOM-style disrupted mask policy.
struct SecomMask;
impl TranspositionMask for SecomMask {
    fn mask(width: usize, rows: usize, order: &[usize]) -> Vec<bool> {
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
                        cooldown = 1;
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
}

fn demonstrate_cipher<P: TranspositionMask>(name: &str, plaintext: &[u8], key: &str) {
    println!("\n==> {} Disrupted Transposition", name);
    println!("Key: {}", key);
    println!("Plaintext: {}", String::from_utf8_lossy(plaintext));

    let cipher = Disrupted::<P>::new(key).expect("Failed to create cipher");

    let mut ciphertext = vec![0u8; plaintext.len()];
    let ct_len = cipher.encrypt(&mut ciphertext, plaintext);
    println!("Ciphertext: {}", String::from_utf8_lossy(&ciphertext[..ct_len]));

    let mut decrypted = vec![0u8; ct_len];
    let pt_len = cipher.decrypt(&mut decrypted, &ciphertext[..ct_len]);
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted[..pt_len]));

    if &decrypted[..pt_len] == plaintext {
        println!("✓ Decryption successful!");
    } else {
        println!("✗ Decryption failed!");
    }
}

fn old_transposition(name: &str, plaintext: &[u8], key: &str) {
    println!("\n==> {} Regular Transposition", name);
    println!("Key: {}", key);
    println!("Plaintext: {}", String::from_utf8_lossy(plaintext));

    let cipher = Transposition::new(key).expect("Failed to create cipher");

    let mut ciphertext = vec![0u8; plaintext.len()];
    let ct_len = cipher.encrypt(&mut ciphertext, plaintext);
    println!("Ciphertext: {}", String::from_utf8_lossy(&ciphertext[..ct_len]));

    let mut decrypted = vec![0u8; ct_len];
    let pt_len = cipher.decrypt(&mut decrypted, &ciphertext[..ct_len]);
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted[..pt_len]));

    if &decrypted[..pt_len] == plaintext {
        println!("✓ Decryption successful!");
    } else {
        println!("✗ Decryption failed!");
    }

}

fn main() {
    println!("Generic Disrupted Transposition Cipher Examples");
    println!("================================================");

    let plaintext = b"ATTACKATDAWN";
    let key = "SUBWAY";

    // Example 0: Old transposition
    old_transposition("Old (Reference)", plaintext, key);

    // Example 1: No mask (regular transposition)
    demonstrate_cipher::<NoMask>("NoMask (Regular)", plaintext, key);

    // Example 2: VIC-style triangular mask
    demonstrate_cipher::<VicMask>("VIC-style", plaintext, key);

    // Example 3: SECOM-style disrupted mask
    demonstrate_cipher::<SecomMask>("SECOM-style", plaintext, key);

    // Example 4: Longer text
    println!("\n==> Longer Example with VIC-style mask");
    let long_text = b"THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG";
    let long_key = "ARABESQUE";
    demonstrate_cipher::<VicMask>("VIC-style (long)", long_text, long_key);
}
