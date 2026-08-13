use std::hint::black_box;

use divan::Bencher;
use sigaba::{
    Block, IndexRotorSetting as SigabaIndexRotorSetting, LargeRotorSet as SigabaRotorSet,
    LargeRotorSetting as SigabaLargeRotorSetting, Orientation as SigabaOrientation, Sigaba,
    SigabaConfig, SigabaIndexPosition, SigabaIndexRotorId, SigabaRotorId, SigabaRotorPosition,
};

const SHORT_PLAINTEXT: &str = "HELLO WORLD";
const SHORT_CIPHERTEXT: &str = "FLQGFQUEQCH";
const LONG_CHUNK: &str = "THE QUICK BROWN FOX ATTACKS AT DAWN ";
const LONG_REPETITIONS: usize = 512;

fn main() {
    verify_fixtures();
    divan::main();
}

fn config(orientation: SigabaOrientation) -> SigabaConfig {
    let large = |id: u8| {
        SigabaLargeRotorSetting::new(
            SigabaRotorId::new(id).unwrap(),
            SigabaRotorPosition::new(14).unwrap(),
            orientation,
        )
    };
    let index = |id: u8| {
        SigabaIndexRotorSetting::new(
            SigabaIndexRotorId::new(id).unwrap(),
            SigabaIndexPosition::ZERO,
        )
    };

    SigabaConfig::new(
        SigabaRotorSet::PekelneyReference,
        [large(0), large(1), large(2), large(3), large(4)],
        [large(5), large(6), large(7), large(8), large(9)],
        [index(0), index(1), index(2), index(3), index(4)],
    )
    .unwrap()
}

fn machine(orientation: SigabaOrientation) -> Sigaba {
    Sigaba::new(config(orientation))
}

fn long_plaintext() -> String {
    LONG_CHUNK.repeat(LONG_REPETITIONS)
}

fn verify_fixtures() {
    let normal = machine(SigabaOrientation::Normal);
    assert_eq!(
        normal.encrypt_text(SHORT_PLAINTEXT).unwrap(),
        SHORT_CIPHERTEXT
    );
    assert_eq!(
        normal.decrypt_text(SHORT_CIPHERTEXT).unwrap(),
        SHORT_PLAINTEXT
    );

    let plaintext = long_plaintext();
    for orientation in [SigabaOrientation::Normal, SigabaOrientation::Reversed] {
        let machine = machine(orientation);
        let ciphertext = machine.encrypt_text(&plaintext).unwrap();
        assert_eq!(machine.decrypt_text(&ciphertext).unwrap(), plaintext);
    }
}

#[divan::bench_group]
mod initialization {
    use super::{Bencher, Sigaba, SigabaOrientation, black_box, config, machine};

    /// Measures typed key validation and construction, without processing text.
    #[divan::bench]
    fn validate_config(bencher: Bencher) {
        bencher.bench_local(|| black_box(config(black_box(SigabaOrientation::Normal))));
    }

    /// Measures the one-time construction of the cached initial core.
    #[divan::bench]
    fn construct_machine(bencher: Bencher) {
        let config = config(SigabaOrientation::Normal);
        bencher.bench_local(|| black_box(Sigaba::new(black_box(config))));
    }

    /// Measures copying the cached initial core plus one contact operation.
    #[divan::bench]
    fn cached_reset_plus_one_contact(bencher: Bencher) {
        let machine = machine(SigabaOrientation::Normal);
        bencher.bench_local(|| {
            black_box(machine.encrypt_text(black_box("A")).unwrap());
        });
    }
}

#[divan::bench_group]
mod text_short {
    use super::{
        Bencher, SHORT_CIPHERTEXT, SHORT_PLAINTEXT, SigabaOrientation, black_box, machine,
    };

    #[divan::bench]
    fn encrypt(bencher: Bencher) {
        let machine = machine(SigabaOrientation::Normal);
        bencher.bench_local(|| {
            black_box(machine.encrypt_text(black_box(SHORT_PLAINTEXT)).unwrap());
        });
    }

    #[divan::bench]
    fn decrypt(bencher: Bencher) {
        let machine = machine(SigabaOrientation::Normal);
        bencher.bench_local(|| {
            black_box(machine.decrypt_text(black_box(SHORT_CIPHERTEXT)).unwrap());
        });
    }
}

#[divan::bench_group]
mod text_long {
    use super::{Bencher, SigabaOrientation, black_box, long_plaintext, machine};

    #[divan::bench]
    fn encrypt_normal(bencher: Bencher) {
        let machine = machine(SigabaOrientation::Normal);
        let plaintext = long_plaintext();
        bencher.bench_local(|| {
            black_box(machine.encrypt_text(black_box(&plaintext)).unwrap());
        });
    }

    #[divan::bench]
    fn decrypt_normal(bencher: Bencher) {
        let machine = machine(SigabaOrientation::Normal);
        let ciphertext = machine.encrypt_text(&long_plaintext()).unwrap();
        bencher.bench_local(|| {
            black_box(machine.decrypt_text(black_box(&ciphertext)).unwrap());
        });
    }

    #[divan::bench]
    fn encrypt_reversed(bencher: Bencher) {
        let machine = machine(SigabaOrientation::Reversed);
        let plaintext = long_plaintext();
        bencher.bench_local(|| {
            black_box(machine.encrypt_text(black_box(&plaintext)).unwrap());
        });
    }

    #[divan::bench]
    fn decrypt_reversed(bencher: Bencher) {
        let machine = machine(SigabaOrientation::Reversed);
        let ciphertext = machine.encrypt_text(&long_plaintext()).unwrap();
        bencher.bench_local(|| {
            black_box(machine.decrypt_text(black_box(&ciphertext)).unwrap());
        });
    }
}

/// The compatibility API writes into a reusable buffer, providing a baseline
/// without the text API's output allocation.
#[divan::bench_group]
mod block_long {
    use super::{Bencher, Block, SigabaOrientation, black_box, long_plaintext, machine};

    #[divan::bench]
    fn encrypt(bencher: Bencher) {
        let machine = machine(SigabaOrientation::Normal);
        let plaintext = long_plaintext();
        let mut output = vec![0_u8; plaintext.len()];

        bencher.bench_local(|| {
            black_box(machine.encrypt(black_box(&mut output), black_box(plaintext.as_bytes())));
        });
    }

    #[divan::bench]
    fn decrypt(bencher: Bencher) {
        let machine = machine(SigabaOrientation::Normal);
        let plaintext = long_plaintext();
        let mut ciphertext = vec![0_u8; plaintext.len()];
        machine.encrypt(&mut ciphertext, plaintext.as_bytes());
        let mut output = vec![0_u8; ciphertext.len()];

        bencher.bench_local(|| {
            black_box(machine.decrypt(black_box(&mut output), black_box(&ciphertext)));
        });
    }
}
