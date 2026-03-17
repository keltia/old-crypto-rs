use old_crypto_rs::{
    ADFGVX, Block, CaesarCipher, Chaocipher, IrregularTransposition, Nihilist, PlayfairCipher,
    SecomCipher, SquareCipher, StraddlingCheckerboard, Transposition, VicCipher, VigenereCipher,
    Wheatstone, AutokeyCipher, AutocryptCipher, helpers, Solitaire,
};

use divan::Bencher;

const KEY_PLAIN: &str = "PTLNBQDEOYSFAVZKGJRIHWXUMC";
const KEY_CIPHER: &str = "HXUCZVAMDSLKPEFJRIGTWOBNYQ";
const PLAIN: &str = "CETOOTESTCHIFFREAVECADFGVXETLESCLESMASTODONETSOCIALX";

fn main() {
    divan::main();
}

#[divan::bench_group]
mod encryption {
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
        let c = VigenereCipher::new("SUBWAY");
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b03_autokey(bencher: Bencher) {
        let c = AutokeyCipher::new("SUBWAY");
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b04_autocrypt(bencher: Bencher) {
        let c = AutocryptCipher::new("SUBWAY");
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b05_square(bencher: Bencher) {
        let c = SquareCipher::new("ARABESQUE", "012345").unwrap();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len() * 2];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b06_playfair(bencher: Bencher) {
        let c = PlayfairCipher::new("ARABESQUE");
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len() * 2];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b07_transposition(bencher: Bencher) {
        let c = Transposition::new("SUBWAY").unwrap();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b08_irregular_transposition(bencher: Bencher) {
        let c = IrregularTransposition::new("SUBWAY").unwrap();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b09_straddling(bencher: Bencher) {
        let c = StraddlingCheckerboard::new("ARABESQUE", "37").unwrap();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len() * 2];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b10_adfgvx(bencher: Bencher) {
        let c = ADFGVX::new("ARABESQUE", "SUBWAY").unwrap();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len() * 2];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b11_nihilist(bencher: Bencher) {
        let c = Nihilist::new("ARABESQUE", "SUBWAY", "37").unwrap();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len() * 2];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b12_vic(bencher: Bencher) {
        let c = VicCipher::new("89", "741776", "IDREAMOFJEANNIEWITHT", "77651").unwrap();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len() * 3];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b13_secom(bencher: Bencher) {
        let c = SecomCipher::new("IDREAMOFJEANNIEWITHT", "ATONESI").unwrap();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len() * 3];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b14_chaocipher(bencher: Bencher) {
        let c = Chaocipher::new(KEY_PLAIN, KEY_CIPHER).unwrap();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b15_solitaire(bencher: Bencher) {
        let c = Solitaire::new_with_passphrase("ARABESQUE");
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len() * 2];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b16_wheatstone(bencher: Bencher) {
        let c = Wheatstone::new(b'M', "CIPHER", "MACHINE").unwrap();
        let fixpt = helpers::fix_double(PLAIN, 'Q');
        let src = fixpt.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }
}

#[divan::bench_group]
mod decryption {
    use super::*;

    #[divan::bench]
    fn b12_vic(bencher: Bencher) {
        let c = VicCipher::new("89", "741776", "IDREAMOFJEANNIEWITHT", "77651").unwrap();
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
        let c = SecomCipher::new("IDREAMOFJEANNIEWITHT", "ATONESI").unwrap();
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
        let c = VigenereCipher::new("SUBWAY");
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
        let c = AutokeyCipher::new("SUBWAY");
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
        let c = AutocryptCipher::new("SUBWAY");
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
        let c = SquareCipher::new("ARABESQUE", "012345").unwrap();
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
        let c = Transposition::new("SUBWAY").unwrap();
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
        let c = IrregularTransposition::new("SUBWAY").unwrap();
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
        let c = Chaocipher::new(KEY_PLAIN, KEY_CIPHER).unwrap();
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
        let c = PlayfairCipher::new("ARABESQUE");
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
        let c = ADFGVX::new("ARABESQUE", "SUBWAY").unwrap();
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
        let c = StraddlingCheckerboard::new("ARABESQUE", "37").unwrap();
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
        let c = Nihilist::new("ARABESQUE", "SUBWAY", "37").unwrap();
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
        let c = Solitaire::new_with_passphrase("ARABESQUE");
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
        let c = Wheatstone::new(b'M', "CIPHER", "MACHINE").unwrap();
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
