//! Benchmark comparing Regular, Irregular, and generic Disrupted transposition implementations.
//!
//! This benchmark verifies that all implementations produce correct results and compares
//! their performance characteristics.

use divan::Bencher;
use old_crypto_rs::helpers::TranspositionMask;
use old_crypto_rs::{Block, Disrupted, IrregularTransposition, Transposition};

const KEY: &str = "SUBWAY";
const PLAIN: &str = "ATTACKATDAWN";
const LONG_PLAIN: &str = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG";

fn main() {
    // Verify correctness before benchmarking
    verify_correctness();

    divan::main();
}

/// Verify that all implementations produce the same results where applicable.
fn verify_correctness() {
    let plaintext = PLAIN.as_bytes();

    // Test Regular transposition
    let regular = Transposition::new(KEY).expect("Failed to create regular transposition");
    let mut ct_regular = vec![0u8; plaintext.len()];
    regular.encrypt(&mut ct_regular, plaintext);
    let mut pt_regular = vec![0u8; plaintext.len()];
    regular.decrypt(&mut pt_regular, &ct_regular);
    assert_eq!(pt_regular, plaintext, "Regular transposition roundtrip failed");

    // Test Irregular transposition
    let irregular = IrregularTransposition::new(KEY).expect("Failed to create irregular transposition");
    let mut ct_irregular = vec![0u8; plaintext.len()];
    irregular.encrypt(&mut ct_irregular, plaintext);
    let mut pt_irregular = vec![0u8; plaintext.len()];
    irregular.decrypt(&mut pt_irregular, &ct_irregular);
    assert_eq!(pt_irregular, plaintext, "Irregular transposition roundtrip failed");

    // Test Disrupted with NoMask (should match Regular)
    let disrupted_no = Disrupted::<NoMask>::new(KEY).expect("Failed to create disrupted no-mask");
    let mut ct_disrupted_no = vec![0u8; plaintext.len()];
    disrupted_no.encrypt(&mut ct_disrupted_no, plaintext);
    let mut pt_disrupted_no = vec![0u8; plaintext.len()];
    disrupted_no.decrypt(&mut pt_disrupted_no, &ct_disrupted_no);
    assert_eq!(pt_disrupted_no, plaintext, "Disrupted NoMask roundtrip failed");
    assert_eq!(ct_disrupted_no, ct_regular, "Disrupted NoMask should match Regular transposition");

    // Test Disrupted with VicMask (should match Irregular)
    let disrupted_vic = Disrupted::<VicMask>::new(KEY).expect("Failed to create disrupted vic-mask");
    let mut ct_disrupted_vic = vec![0u8; plaintext.len()];
    disrupted_vic.encrypt(&mut ct_disrupted_vic, plaintext);
    let mut pt_disrupted_vic = vec![0u8; plaintext.len()];
    disrupted_vic.decrypt(&mut pt_disrupted_vic, &ct_disrupted_vic);
    assert_eq!(pt_disrupted_vic, plaintext, "Disrupted VicMask roundtrip failed");
    assert_eq!(ct_disrupted_vic, ct_irregular, "Disrupted VicMask should match Irregular transposition");

    // Test Disrupted with SecomMask
    let disrupted_secom = Disrupted::<SecomMask>::new(KEY).expect("Failed to create disrupted secom-mask");
    let mut ct_disrupted_secom = vec![0u8; plaintext.len()];
    disrupted_secom.encrypt(&mut ct_disrupted_secom, plaintext);
    let mut pt_disrupted_secom = vec![0u8; plaintext.len()];
    disrupted_secom.decrypt(&mut pt_disrupted_secom, &ct_disrupted_secom);
    assert_eq!(pt_disrupted_secom, plaintext, "Disrupted SecomMask roundtrip failed");

    println!("✓ All transposition implementations verified correct");
    println!("  Regular:         {} → {}",
             String::from_utf8_lossy(&ct_regular),
             String::from_utf8_lossy(&pt_regular));
    println!("  Irregular:       {} → {}",
             String::from_utf8_lossy(&ct_irregular),
             String::from_utf8_lossy(&pt_irregular));
    println!("  Disrupted NoMask: {} → {}",
             String::from_utf8_lossy(&ct_disrupted_no),
             String::from_utf8_lossy(&pt_disrupted_no));
    println!("  Disrupted Vic:    {} → {}",
             String::from_utf8_lossy(&ct_disrupted_vic),
             String::from_utf8_lossy(&pt_disrupted_vic));
    println!("  Disrupted Secom:  {} → {}",
             String::from_utf8_lossy(&ct_disrupted_secom),
             String::from_utf8_lossy(&pt_disrupted_secom));
}

// Mask implementations for benchmarking

/// No masking - equivalent to regular transposition.
struct NoMask;
impl TranspositionMask for NoMask {
    fn mask(_width: usize, rows: usize, _order: &[usize]) -> Vec<bool> {
        vec![false; _width * rows]
    }
}

/// VIC-style triangular mask - equivalent to irregular transposition.
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

/// SECOM-style disrupted mask with cooldown periods.
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

// Encryption benchmarks

#[divan::bench_group(name = "encrypt_short")]
mod encrypt_short {
    use super::*;

    #[divan::bench]
    fn regular(bencher: Bencher) {
        let cipher = Transposition::new(KEY).unwrap();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            cipher.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn irregular(bencher: Bencher) {
        let cipher = IrregularTransposition::new(KEY).unwrap();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            cipher.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn disrupted_no_mask(bencher: Bencher) {
        let cipher = Disrupted::<NoMask>::new(KEY).unwrap();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            cipher.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn disrupted_vic_mask(bencher: Bencher) {
        let cipher = Disrupted::<VicMask>::new(KEY).unwrap();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            cipher.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn disrupted_secom_mask(bencher: Bencher) {
        let cipher = Disrupted::<SecomMask>::new(KEY).unwrap();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            cipher.encrypt(&mut dst, src);
        });
    }
}

#[divan::bench_group(name = "encrypt_long")]
mod encrypt_long {
    use super::*;

    #[divan::bench]
    fn regular(bencher: Bencher) {
        let cipher = Transposition::new(KEY).unwrap();
        let src = LONG_PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            cipher.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn irregular(bencher: Bencher) {
        let cipher = IrregularTransposition::new(KEY).unwrap();
        let src = LONG_PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            cipher.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn disrupted_no_mask(bencher: Bencher) {
        let cipher = Disrupted::<NoMask>::new(KEY).unwrap();
        let src = LONG_PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            cipher.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn disrupted_vic_mask(bencher: Bencher) {
        let cipher = Disrupted::<VicMask>::new(KEY).unwrap();
        let src = LONG_PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            cipher.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn disrupted_secom_mask(bencher: Bencher) {
        let cipher = Disrupted::<SecomMask>::new(KEY).unwrap();
        let src = LONG_PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            cipher.encrypt(&mut dst, src);
        });
    }
}

// Decryption benchmarks

#[divan::bench_group(name = "decrypt_short")]
mod decrypt_short {
    use super::*;

    #[divan::bench]
    fn regular(bencher: Bencher) {
        let cipher = Transposition::new(KEY).unwrap();
        let src = PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len()];
        cipher.encrypt(&mut ct, src);
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            cipher.decrypt(&mut dst, &ct);
        });
    }

    #[divan::bench]
    fn irregular(bencher: Bencher) {
        let cipher = IrregularTransposition::new(KEY).unwrap();
        let src = PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len()];
        cipher.encrypt(&mut ct, src);
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            cipher.decrypt(&mut dst, &ct);
        });
    }

    #[divan::bench]
    fn disrupted_no_mask(bencher: Bencher) {
        let cipher = Disrupted::<NoMask>::new(KEY).unwrap();
        let src = PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len()];
        cipher.encrypt(&mut ct, src);
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            cipher.decrypt(&mut dst, &ct);
        });
    }

    #[divan::bench]
    fn disrupted_vic_mask(bencher: Bencher) {
        let cipher = Disrupted::<VicMask>::new(KEY).unwrap();
        let src = PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len()];
        cipher.encrypt(&mut ct, src);
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            cipher.decrypt(&mut dst, &ct);
        });
    }

    #[divan::bench]
    fn disrupted_secom_mask(bencher: Bencher) {
        let cipher = Disrupted::<SecomMask>::new(KEY).unwrap();
        let src = PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len()];
        cipher.encrypt(&mut ct, src);
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            cipher.decrypt(&mut dst, &ct);
        });
    }
}

#[divan::bench_group(name = "decrypt_long")]
mod decrypt_long {
    use super::*;

    #[divan::bench]
    fn regular(bencher: Bencher) {
        let cipher = Transposition::new(KEY).unwrap();
        let src = LONG_PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len()];
        cipher.encrypt(&mut ct, src);
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            cipher.decrypt(&mut dst, &ct);
        });
    }

    #[divan::bench]
    fn irregular(bencher: Bencher) {
        let cipher = IrregularTransposition::new(KEY).unwrap();
        let src = LONG_PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len()];
        cipher.encrypt(&mut ct, src);
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            cipher.decrypt(&mut dst, &ct);
        });
    }

    #[divan::bench]
    fn disrupted_no_mask(bencher: Bencher) {
        let cipher = Disrupted::<NoMask>::new(KEY).unwrap();
        let src = LONG_PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        let mut ct = vec![0u8; src.len()];
        cipher.encrypt(&mut ct, src);
        bencher.bench_local(|| {
            cipher.decrypt(&mut dst, &ct);
        });
    }

    #[divan::bench]
    fn disrupted_vic_mask(bencher: Bencher) {
        let cipher = Disrupted::<VicMask>::new(KEY).unwrap();
        let src = LONG_PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len()];
        cipher.encrypt(&mut ct, src);
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            cipher.decrypt(&mut dst, &ct);
        });
    }

    #[divan::bench]
    fn disrupted_secom_mask(bencher: Bencher) {
        let cipher = Disrupted::<SecomMask>::new(KEY).unwrap();
        let src = LONG_PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len()];
        cipher.encrypt(&mut ct, src);
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            cipher.decrypt(&mut dst, &ct);
        });
    }
}
