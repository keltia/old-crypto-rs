use divan::Bencher;
use kl_7::{Contact26, Kl7, Kl7Config};
use std::hint::black_box;

const REFERENCE_KEY_YAML: &str = include_str!("../config/reference.yaml");
const SHORT_PLAINTEXT: &str = "THE QUICK BROWN FOX JUMPS OVER THE LAXY DOG";
const LONG_CHUNK: &str = "THE QUICK BROWN FOX ATTACKS AT DAWN ";
const LONG_REPETITIONS: usize = 256;

fn main() {
    verify_fixtures();
    divan::main();
}

fn verify_fixtures() {
    let kl7 = Kl7::new(Kl7Config::uss_beagle());
    let cipher = kl7.encrypt_text(SHORT_PLAINTEXT).unwrap();
    let dec = kl7.decrypt_text(&cipher).unwrap();
    assert_eq!(dec, SHORT_PLAINTEXT);
}

fn long_plaintext() -> String {
    LONG_CHUNK.repeat(LONG_REPETITIONS)
}

#[divan::bench_group]
mod initialization {
    use super::{black_box, Bencher, Kl7, Kl7Config, REFERENCE_KEY_YAML};

    #[divan::bench]
    fn parse_key_yaml(bencher: Bencher) {
        bencher.bench_local(|| {
            black_box(Kl7Config::from_yaml(black_box(REFERENCE_KEY_YAML)).unwrap())
        });
    }

    #[divan::bench]
    fn construct_machine(bencher: Bencher) {
        let config = Kl7Config::uss_beagle();
        bencher.bench_local(|| black_box(Kl7::new(black_box(config.clone()))));
    }
}

#[divan::bench_group]
mod throughput {
    use super::{black_box, long_plaintext, Bencher, Contact26, Kl7, Kl7Config, SHORT_PLAINTEXT};

    #[divan::bench]
    fn encrypt_single_contact_with_stepping(bencher: Bencher) {
        let config = Kl7Config::uss_beagle();
        let mut core = config.build_core();
        let contact = Contact26::new(0).unwrap();

        bencher.bench_local(|| {
            black_box(core.encipher_contact(black_box(contact)).unwrap());
        });
    }

    #[divan::bench]
    fn encrypt_short_message(bencher: Bencher) {
        let kl7 = Kl7::new(Kl7Config::uss_beagle());
        bencher.bench_local(|| {
            black_box(kl7.encrypt_text(black_box(SHORT_PLAINTEXT)).unwrap());
        });
    }

    #[divan::bench]
    fn encrypt_long_stream(bencher: Bencher) {
        let kl7 = Kl7::new(Kl7Config::uss_beagle());
        let text = long_plaintext();
        bencher.bench_local(|| {
            black_box(kl7.encrypt_text(black_box(&text)).unwrap());
        });
    }

    #[divan::bench]
    fn decrypt_long_stream(bencher: Bencher) {
        let kl7 = Kl7::new(Kl7Config::uss_beagle());
        let text = long_plaintext();
        let cipher = kl7.encrypt_text(&text).unwrap();
        bencher.bench_local(|| {
            black_box(kl7.decrypt_text(black_box(&cipher)).unwrap());
        });
    }
}
