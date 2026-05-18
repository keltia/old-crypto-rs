use std::hint::black_box;

use divan::Bencher;

use old_crypto_rs::helpers::{SC_ALPHABET, shuffle, transp_shuffle, condense, condense_str, fix_double_aligned, expand, fix_double, to_numeric};
use old_crypto_rs::column_order_from_digits;

const PLAIN: &str = "CETOOTESTCHIFFREAVECADFGVXETLESCLESMASTODONETSOCIAL";

fn main() {
    divan::main();
}

const KEY: &str = "ARABESQUE";

#[divan::bench_group]
mod shuffle {
    use super::*;

    #[divan::bench]
    fn bench_shuffle(bencher: Bencher) {
        bencher.bench_local(|| {
            black_box(shuffle(KEY, SC_ALPHABET));
        });
    }

    #[divan::bench]
    fn bench_transp_shuffle(bencher: Bencher) {
        bencher.bench_local(|| {
            let _ = black_box(transp_shuffle(KEY, SC_ALPHABET));
        });
    }
}

#[divan::bench_group]
mod condense {
    use super::*;

    #[divan::bench]
    fn bench_condense(bencher: Bencher) {
        bencher.bench_local(|| {
            black_box(condense(PLAIN));
        });
    }

    #[divan::bench]
    fn bench_condense_str(bencher: Bencher) {
        bencher.bench_local(|| {
            black_box(condense_str(PLAIN));
        });
    }
}

#[divan::bench_group]
mod fix_double {
    use super::*;

    #[divan::bench]
    fn bench_fix_double(bencher: Bencher) {
        bencher.bench_local(|| {
            black_box(fix_double(PLAIN, 'Q'));
        });
    }

    #[divan::bench]
    fn bench_expand(bencher: Bencher) {
        bencher.bench_local(|| {
            black_box(expand(PLAIN.as_bytes()));
        });
    }


    #[divan::bench]
    fn bench_double_aligned(bencher: Bencher) {
        bencher.bench_local(|| {
            black_box(fix_double_aligned(PLAIN, 'Q'));
        });
    }
}

#[divan::bench_group]
mod to_numeric {
    use super::*;

    #[divan::bench]
    fn bench_to_numeric(bencher: Bencher) {
        bencher.bench_local(|| {
            black_box(to_numeric("8238965327"));
        })
    }

    #[divan::bench]
    fn bench_column_order_from_digits(bencher: Bencher) {
        bencher.bench_local(|| {
            black_box(column_order_from_digits(&[8,2,3,8,9,6,5,3,2,7]));
        });
    }
}
