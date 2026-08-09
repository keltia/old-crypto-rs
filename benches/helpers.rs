use std::hint::black_box;

use divan::Bencher;

use old_crypto_rs::column_order_from_digits;
use old_crypto_rs::helpers::{
    SC_ALPHABET, condense, condense_str, expand, fix_double, fix_double_aligned, shuffle,
    to_numeric, to_numeric_old, to_numeric_one, to_numeric_one_old, transp_shuffle,
};

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
    use std::collections::HashSet;
    use ahash::AHashSet;
    use super::*;

    #[divan::bench]
    fn bench_condense(bencher: Bencher) {
        bencher.bench_local(|| {
            black_box(condense(PLAIN));
        });
    }

    #[divan::bench]
    fn bench_condense_ahash(bencher: Bencher) {
        bencher.bench_local(|| {
            black_box(condense_ahash(PLAIN));
        });
    }

    #[divan::bench]
    fn bench_condense_str(bencher: Bencher) {
        bencher.bench_local(|| {
            black_box(condense_str(PLAIN));
        });
    }

    pub fn condense_ahash(str: &str) -> String {
    let mut seen = AHashSet::with_capacity(str.len());
    let mut condensed = String::with_capacity(str.len());

    for ch in str.chars() {
        if seen.insert(ch) {
            condensed.push(ch);
        }
    }
    condensed
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
    fn bench_to_numeric_old(bencher: Bencher) {
        bencher.bench_local(|| {
            black_box(to_numeric_old("8238965327"));
        })
    }

    #[divan::bench]
    fn bench_to_numeric_one(bencher: Bencher) {
        bencher.bench_local(|| {
            black_box(to_numeric_one("8238965327"));
        })
    }

    #[divan::bench]
    fn bench_to_numeric_one_old(bencher: Bencher) {
        bencher.bench_local(|| {
            black_box(to_numeric_one_old("8238965327"));
        })
    }

    #[divan::bench]
    fn bench_column_order_from_digits(bencher: Bencher) {
        bencher.bench_local(|| {
            black_box(column_order_from_digits(&[8, 2, 3, 8, 9, 6, 5, 3, 2, 7]));
        });
    }
}

#[divan::bench_group]
mod chainadd {
    use super::*;

    fn chainadd_inplace(a: &mut [u8]) {
        let l = a.len();
        if l < 2 {
            return;
        }
        for i in 0..l - 1 {
            a[i] = (a[i] + a[i + 1]) % 10;
        }
        let first = a[0];
        a[l - 1] = (a[l - 1] + first) % 10;
    }

    /// Performs chain addition on a vector, and returns the result.
    ///
    /// Chain addition adds each element to its right neighbor (wrapping around at the end)
    /// and stores the result modulo 10 in the original position.
    ///
    /// # Arguments
    ///
    /// * `a` - Slice to perform chain addition on
    ///
    fn chainadd(a: &[u8]) -> Vec<u8> {
        let l = a.len();
        let mut r = Vec::with_capacity(l);

        if l < 2 {
            return vec![];
        }
        for i in 0..l - 1 {
            r.push((a[i] + a[i + 1]) % 10);
        }
        r.push((a[l - 1] + r[0]) % 10);
        r.to_vec()
    }

    #[divan::bench]
    fn test_chainadd_inplace(bencher: Bencher) {
        let mut a = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        bencher.bench_local(|| {
            black_box(chainadd_inplace(&mut a));
        });
    }

    #[divan::bench]
    fn test_chainadd(bencher: Bencher) {
        let a = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        bencher.bench_local(|| {
            black_box(chainadd(&a));
        });
    }
}

#[divan::bench_group]
mod smallv {
    use super::*;
    use smallvec::SmallVec;

    type Digits10 = SmallVec<[u8; 10]>;
    type Digits16 = SmallVec<[u8; 16]>;
    type Order16 = SmallVec<[usize; 16]>;

    /// Benchmark-local SmallVec variant of column_order_from_digits.
    fn column_order_from_digits_smallvec(key: &[u8]) -> Order16 {
        let mut indexed: SmallVec<[(usize, u8); 16]> =
            key.iter().enumerate().map(|(i, &b)| (i, b)).collect();
        indexed.sort_by_key(|&(i, b)| (b, i));

        indexed.into_iter().map(|(i, _)| i).collect()
    }

    fn chainadd_smallvec(a: &[u8]) -> Digits16 {
        let l = a.len();
        let mut out = Digits16::new();

        if l < 2 {
            return out;
        }

        for i in 0..l - 1 {
            out.push((a[i] + a[i + 1]) % 10);
        }
        out.push((a[l - 1] + out[0]) % 10);
        out
    }

    #[divan::bench]
    fn bench_column_order_from_digits_smallvec(bencher: Bencher) {
        bencher.bench_local(|| {
            black_box(column_order_from_digits_smallvec(&[
                8, 2, 3, 8, 9, 6, 5, 3, 2, 7,
            ]));
        });
    }

    #[divan::bench]
    fn bench_chainadd_smallvec(bencher: Bencher) {
        let a = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        bencher.bench_local(|| {
            black_box(chainadd_smallvec(&a));
        });
    }
}
