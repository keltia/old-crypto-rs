use old_crypto_rs::{
    ADFGVXCipher, Block, CaesarCipher, Chaocipher, IrregularTransposition, Nihilist, PlayfairCipher,
    SecomCipher, SquareCipher, Straddling, Transposition, VicCipher, VigenereCipher,
    Wheatstone, AutokeyCipher, AutocryptCipher, helpers, Solitaire,
};

use divan::Bencher;

const CHAOS_PLAIN: &str = "PTLNBQDEOYSFAVZKGJRIHWXUMC";
const CHAOS_CIPHER: &str = "HXUCZVAMDSLKPEFJRIGTWOBNYQ";
const PLAIN: &str = "CETOOTESTCHIFFREAVECADFGVXETLESCLESMASTODONETSOCIALX";

const KEY1: &str = "SUBWAY";
const KEY2: &str = "ARABESQUE";
const KEY3: &str = "CIPHER";
const KEY4: &str = "MACHINE";
const PASSPHRASE: &str = "IDREAMOFJEANNIEWITHT";

fn main() {
    divan::main();
}

#[divan::bench_group]
mod b0_encryption {
    use old_crypto_rs::helpers::{English, LatinSC, Latin36, Numeric6};
    use super::*;

    #[divan::bench]
    fn b01_caesar(bencher: Bencher) {
        let c = CaesarCipher::new(3);
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b02_vigenere(bencher: Bencher) {
        let c = VigenereCipher::new(KEY1);
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b03_autokey(bencher: Bencher) {
        let c = AutokeyCipher::new(KEY1);
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b04_autocrypt(bencher: Bencher) {
        let c = AutocryptCipher::new(KEY1);
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b05_square(bencher: Bencher) {
        let c = SquareCipher::<Numeric6, Latin36>::new(KEY2).unwrap();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len() * 2];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b06_playfair(bencher: Bencher) {
        let c = PlayfairCipher::new(KEY2);
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len() * 2];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b07_transposition(bencher: Bencher) {
        let c = Transposition::new(KEY1).unwrap();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b08_irregular_transposition(bencher: Bencher) {
        let c = IrregularTransposition::new(KEY1).unwrap();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b09_straddling(bencher: Bencher) {
        let c = Straddling::<LatinSC, English>::new(KEY2, "37").unwrap();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len() * 2];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b10_adfgvx(bencher: Bencher) {
        let c = ADFGVXCipher::new(KEY2, KEY1).unwrap();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len() * 2];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b11_nihilist(bencher: Bencher) {
        let c = Nihilist::<LatinSC, English>::new(KEY2, KEY1, "37").unwrap();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len() * 2];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b12_vic(bencher: Bencher) {
        let c = VicCipher::<LatinSC, English>::new("89", "741776", PASSPHRASE, "77651").unwrap();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len() * 3];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b13_secom(bencher: Bencher) {
        let c = SecomCipher::new(PASSPHRASE, "ATONESI").unwrap();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len() * 3];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b14_chaocipher(bencher: Bencher) {
        let c = Chaocipher::new(CHAOS_PLAIN, CHAOS_CIPHER).unwrap();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b15_solitaire(bencher: Bencher) {
        let c = Solitaire::new_with_passphrase(KEY2);
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len() * 2];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b16_wheatstone(bencher: Bencher) {
        let c = Wheatstone::new(b'M', KEY3, KEY4).unwrap();
        let fixpt = helpers::fix_double(PLAIN, 'Q');
        let src = fixpt.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }
}

#[divan::bench_group]
mod b1_decryption {
    use old_crypto_rs::helpers::{English, Latin36, LatinSC, Numeric6};
    use super::*;

    #[divan::bench]
    fn b12_vic(bencher: Bencher) {
        let c = VicCipher::<LatinSC, English>::new("89", "741776", PASSPHRASE, "77651").unwrap();
        let src = PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len() * 3];
        c.encrypt(&mut ct, src);
        let ct_len = ct.iter().position(|&x| x == 0).unwrap_or(ct.len());
        let ct_trimmed = &ct[..ct_len];
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.decrypt(&mut dst, ct_trimmed);
        });
    }

    #[divan::bench]
    fn b13_secom(bencher: Bencher) {
        let c = SecomCipher::new(PASSPHRASE, "ATONESI").unwrap();
        let src = PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len() * 2];
        c.encrypt(&mut ct, src);
        let ct_len = ct.iter().position(|&x| x == 0).unwrap_or(ct.len());
        let ct_trimmed = &ct[..ct_len];
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.decrypt(&mut dst, ct_trimmed);
        });
    }

    #[divan::bench]
    fn b01_caesar(bencher: Bencher) {
        let c = CaesarCipher::new(3);
        let src = PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len()];
        c.encrypt(&mut ct, src);
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.decrypt(&mut dst, &ct);
        });
    }

    #[divan::bench]
    fn b02_vigenere(bencher: Bencher) {
        let c = VigenereCipher::new(KEY1);
        let src = PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len()];
        c.encrypt(&mut ct, src);
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.decrypt(&mut dst, &ct);
        });
    }

    #[divan::bench]
    fn b03_autokey(bencher: Bencher) {
        let c = AutokeyCipher::new(KEY1);
        let src = PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len()];
        c.encrypt(&mut ct, src);
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.decrypt(&mut dst, &ct);
        });
    }

    #[divan::bench]
    fn b04_autocrypt(bencher: Bencher) {
        let c = AutocryptCipher::new(KEY1);
        let src = PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len()];
        c.encrypt(&mut ct, src);
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.decrypt(&mut dst, &ct);
        });
    }

    #[divan::bench]
    fn b05_square(bencher: Bencher) {
        let c = SquareCipher::<Numeric6,Latin36>::new(KEY2).unwrap();
        let src = PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len() * 2];
        c.encrypt(&mut ct, src);
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.decrypt(&mut dst, &ct);
        });
    }

    #[divan::bench]
    fn b07_transposition(bencher: Bencher) {
        let c = Transposition::new(KEY1).unwrap();
        let src = PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len()];
        c.encrypt(&mut ct, src);
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.decrypt(&mut dst, &ct);
        });
    }

    #[divan::bench]
    fn b08_irregular_transposition(bencher: Bencher) {
        let c = IrregularTransposition::new(KEY1).unwrap();
        let src = PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len()];
        c.encrypt(&mut ct, src);
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.decrypt(&mut dst, &ct);
        });
    }

    #[divan::bench]
    fn b14_chaocipher(bencher: Bencher) {
        let c = Chaocipher::new(CHAOS_PLAIN, CHAOS_CIPHER).unwrap();
        let src = PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len()];
        c.encrypt(&mut ct, src);
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.decrypt(&mut dst, &ct);
        });
    }

    #[divan::bench]
    fn b06_playfair(bencher: Bencher) {
        let c = PlayfairCipher::new(KEY2);
        let src = PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len() * 2];
        let ct_len = c.encrypt(&mut ct, src);
        let ct = &ct[..ct_len];
        let mut dst = vec![0u8; ct.len()];
        bencher.bench_local(|| {
            c.decrypt(&mut dst, ct);
        });
    }

    #[divan::bench]
    fn b10_adfgvx(bencher: Bencher) {
        let c = ADFGVXCipher::new(KEY2, KEY1).unwrap();
        let src = PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len() * 2];
        c.encrypt(&mut ct, src);
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.decrypt(&mut dst, &ct);
        });
    }

    #[divan::bench]
    fn b09_straddling(bencher: Bencher) {
        let c = Straddling::<LatinSC, English>::new(KEY2, "37").unwrap();
        let src = PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len() * 2];
        c.encrypt(&mut ct, src);
        let mut dst = vec![0u8; ct.len()];
        bencher.bench_local(|| {
            c.decrypt(&mut dst, &ct);
        });
    }

    #[divan::bench]
    fn b11_nihilist(bencher: Bencher) {
        let c = Nihilist::<LatinSC, English>::new(KEY2, KEY1, "37").unwrap();
        let src = PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len() * 2];
        c.encrypt(&mut ct, src);
        let mut dst = vec![0u8; ct.len()];
        bencher.bench_local(|| {
            c.decrypt(&mut dst, &ct);
        });
    }

    #[divan::bench]
    fn b15_solitaire(bencher: Bencher) {
        let c = Solitaire::new_with_passphrase(KEY2);
        let src = PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len() * 2];
        c.encrypt(&mut ct, src);
        let mut dst = vec![0u8; ct.len()];
        bencher.bench_local(|| {
            c.decrypt(&mut dst, &ct);
        });
    }

    #[divan::bench]
    fn b16_wheatstone(bencher: Bencher) {
        let c = Wheatstone::new(b'M', KEY3, KEY4).unwrap();
        let fixpt = helpers::fix_double(PLAIN, 'Q');
        let src = fixpt.as_bytes();
        let mut ct = vec![0u8; src.len()];
        c.encrypt(&mut ct, src);
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.decrypt(&mut dst, &ct);
        });
    }
}
