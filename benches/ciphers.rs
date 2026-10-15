use old_crypto_rs::{
    ADFGVXCipher, AutocryptCipher, AutokeyCipher, Block, CaesarCipher, Chaocipher,
    IrregularTransposition, Nihilist, PlayfairCipher, SecomCipher, Solitaire, SquareCipher,
    Straddling, Transposition, VicCipher, VigenereCipher, Wheatstone, helpers,
};

use divan::Bencher;
use fialka::{
    Block as _, Commutator as FialkaCommutator, Fialka, FialkaConfig,
    RotorSeries as FialkaRotorSeries,
};
use old_crypto_rs::helpers::{English, Horizontal, LatinSC};
use sigaba::{
    Block as _, IndexRotorSetting as SigabaIndexRotorSetting, LargeRotorSet as SigabaRotorSet,
    LargeRotorSetting as SigabaLargeRotorSetting, Orientation as SigabaOrientation, Sigaba,
    SigabaConfig, SigabaIndexPosition, SigabaIndexRotorId, SigabaRotorId, SigabaRotorPosition,
};

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

type BenchVic = VicCipher<LatinSC, Horizontal, English>;

fn bench_sigaba() -> Sigaba {
    let large = |id: u8| {
        SigabaLargeRotorSetting::new(
            SigabaRotorId::new(id).unwrap(),
            SigabaRotorPosition::new(14).unwrap(),
            SigabaOrientation::Normal,
        )
    };
    let index = |id: u8| {
        SigabaIndexRotorSetting::new(
            SigabaIndexRotorId::new(id).unwrap(),
            SigabaIndexPosition::ZERO,
        )
    };

    Sigaba::new(
        SigabaConfig::new(
            SigabaRotorSet::PekelneyReference,
            [large(0), large(1), large(2), large(3), large(4)],
            [large(5), large(6), large(7), large(8), large(9)],
            [index(0), index(1), index(2), index(3), index(4)],
        )
        .unwrap(),
    )
}

fn bench_fialka() -> Fialka {
    Fialka::new(FialkaConfig::overall_base(
        FialkaRotorSeries::Polish3K,
        FialkaCommutator::identity(),
    ))
}

fn fialka_plaintext() -> Vec<u8> {
    PLAIN.bytes().map(|letter| letter - b'A').collect()
}

use purple::{
    Purple, PurpleAlphabet, PurpleConfig, PurpleMotion, SwitchPosition, TwentiesSwitchId,
};
fn bench_purple() -> Purple {
    use TwentiesSwitchId::{One, Three, Two};

    let position = |n| SwitchPosition::new(n).unwrap();
    let config = PurpleConfig::new(
        PurpleAlphabet::new("NOKTYUXEQLHBRMPDICJASVWGZF").unwrap(),
        position(9),
        [position(1), position(24), position(6)],
        PurpleMotion::new(Two, Three, One).unwrap(),
    );

    Purple::new(config)
}

#[divan::bench_group]
mod b0_encryption {
    use super::*;
    use old_crypto_rs::helpers::{English, Horizontal, Latin36, LatinSC, Numeric6};

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
        let c = BenchVic::new("741776", PASSPHRASE, "77651", 6).unwrap();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len() * 3];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b13_secom(bencher: Bencher) {
        let c = SecomCipher::<English>::new(PASSPHRASE).unwrap();
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

    #[divan::bench]
    fn b17_sigaba(bencher: Bencher) {
        let c = bench_sigaba();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }

    #[divan::bench]
    fn b18_fialka(bencher: Bencher) {
        let c = bench_fialka();
        let src = fialka_plaintext();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, &src);
        });
    }

    #[divan::bench]
    fn b19_purple(bencher: Bencher) {
        let c = bench_purple();
        let src = PLAIN.as_bytes();
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.encrypt(&mut dst, src);
        });
    }
}

#[divan::bench_group]
mod b1_decryption {
    use super::*;
    use old_crypto_rs::helpers::{English, Horizontal, Latin36, LatinSC, Numeric6};

    #[divan::bench]
    fn b12_vic(bencher: Bencher) {
        let c = BenchVic::new("741776", PASSPHRASE, "77651", 6).unwrap();
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
        let c = SecomCipher::<English>::new(PASSPHRASE).unwrap();
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
        let c = SquareCipher::<Numeric6, Latin36>::new(KEY2).unwrap();
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

    #[divan::bench]
    fn b17_sigaba(bencher: Bencher) {
        let c = bench_sigaba();
        let src = PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len()];
        c.encrypt(&mut ct, src);
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.decrypt(&mut dst, &ct);
        });
    }

    #[divan::bench]
    fn b18_fialka(bencher: Bencher) {
        let c = bench_fialka();
        let src = fialka_plaintext();
        let mut ct = vec![0u8; src.len()];
        c.encrypt(&mut ct, &src);
        let mut dst = vec![0u8; src.len()];
        bencher.bench_local(|| {
            c.decrypt(&mut dst, &ct);
        });
    }

    #[divan::bench]
    fn b19_purple(bencher: Bencher) {
        let c = bench_purple();
        let src = PLAIN.as_bytes();
        let mut ct = vec![0u8; src.len()];
        let written = c.encrypt(&mut ct, src);
        let mut dst = vec![0u8; written];
        bencher.bench_local(|| {
            c.decrypt(&mut dst, &ct[..written]);
        });
    }
}
