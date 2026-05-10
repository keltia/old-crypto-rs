# old-crypto-rs — Old paper & pencil ciphers in Rust.

[![dependency status](https://deps.rs/repo/github/keltia/old-crypto-rs/status.svg)](https://deps.rs/repo/github/keltia/old-crypto-rs)
[![](https://img.shields.io/crates/v/old-crypto-rs.svg)](https://crates.io/crates/old-crypto-rs)
[![Docs](https://docs.rs/old-crypto-rs/badge.svg)](https://docs.rs/old-crypto-rs)
[![GitHub release](https://img.shields.io/github/release/keltia/old-crypto-rs.svg)](https://github.com/keltia/old-crypto-rs/releases/)

[![SemVer](https://img.shields.io/badge/semver-2.0.0-blue)](https://semver.org/spec/v2.0.0.html)
[![License](https://img.shields.io/badge/license-MIT-red.svg?style=flat)](https://raw.githubusercontent.com/keltia/old-crypto-rs/main/LICENSE)

`old-crypto-rs` is a [Rust](https://rust-lang.org/) evolution of my [cipher](https://github.com/keltia/cipher) Go package,
which was a port of my [old-crypto](https://github.com/keltia/old-crypto) Ruby code.

>NOTE: Neither package is currently maintained, only this one in Rust.  I do not plan to retrofit the added algorithms
>from here into either.

Part of the conversion has been done through the AI plugin inside RustRover called Junie.

It features a simple CLI-based tool called `old-crypto` which serve both as a collection of use-cases for the library,
and an easy way to use it.  It now uses [ratatui](https://crates.io/crates/ratatui) to provide an interactive
TUI.  Key bindings and the whole UI are still a work in progress, this is my first TUI program, in fact.

**Work in progress, still incomplete**

## Table of content

- [Features](#features)
- [Installation](#installation)
- [TODO](#todo)
- [Contributing](#contributing)

## Features

It currently implements a few more compared to the Go/Ruby code, namely:

- Caesar (you can choose the shift number)
- Vigenère and its 2 autoclave variants
- Simple transposition (can be used with other ciphers as super-encipherment)
- Polybius square bi-grammatic cipher (for ADFGVX = polybius + transposition)
- Playfair
- Irregular transposition (can be used with other ciphers as super-encipherment cf. VIC Cipher)
- ADFGVX (6x6 square including numbers)
- Straddling Checkerboard (for the Nihilist & VIC ciphers)
- Nihilist cipher (transposition as super-encipherment)
- VIC Cipher (straddling checkerboard followed by two transpositions, one regular
  and an irregular one)
- SECOM (a field cipher closely related to the VIC cipher, but different)
- Solitaire cipher, a made-up cipher created by Bruce Schneier

It also implements simulation for some cipher devices/machines:
- Chaocipher
- Wheatstone cipher machine
- SIGABA, a US cipher machine from WWII

It does not try to reinvent the wheel and implements the `Block` trait, copying the Go interface for block ciphers.
Most of these ciphers can be mixed, just like The VIC or the ADFGVX ciphers.  Some implementations were pretty
naive, so I am now working to improve them.

## Installation

Like many Rust crates, the installation is straightforward:

    cargo install old-crypto-rs

> NOTE: the crate is not yet published on crates.io,

or

    git clone https://github.com/keltia/old-crypto-rs.git
    cd old-crypto-rs
    cargo nextest run
    cargo bench

The library is fetched, compiled and installed. You can find a "demo" program in the `examples` directory, to showcase
all ciphers; it also checks that you can decrypt back to the original plaintext.

    cargo run --example demo

There will also be a TUI tool called `old-crypto` which can be used to encrypt/decrypt text.

To run the TUI:

    cargo run --bin old-crypto

## Features

The SIGABA cipher machine is still a work in progress, so it has been put under the `sigaba` feature flag.

## Benchmarks & Tests

I tried to provide benchmarks for all ciphers (including key scheduling/expansion) and in some cases several
implementations.

You can run them with

    cargo nextest run
    cargo bench

## Benchmarks

PC, AMD 7700X, 32 GB RAM, 500 GB M2 SSD, Win 11 25H2

```text
cargo bench --bench=ciphers

Timer precision: 100 ns
ciphers                            fastest       │ slowest       │ median        │ mean          │ samples │ iters
├─ b0_encryption                                 │               │               │               │         │
│  ├─ b01_caesar                   20.89 ns      │ 27.14 ns      │ 20.89 ns      │ 21.07 ns      │ 100     │ 51200
│  ├─ b02_vigenere                 199.8 ns      │ 13.19 µs      │ 299.8 ns      │ 432.8 ns      │ 100     │ 100
│  ├─ b03_autokey                  134.9 ns      │ 173.2 ns      │ 136.5 ns      │ 137.3 ns      │ 100     │ 12800
│  ├─ b04_autocrypt                56.44 ns      │ 441.2 ns      │ 56.83 ns      │ 61.26 ns      │ 100     │ 25600
│  ├─ b05_square                   32.02 ns      │ 57.22 ns      │ 32.22 ns      │ 33.29 ns      │ 100     │ 51200
│  ├─ b06_playfair                 393.5 ns      │ 1.977 µs      │ 496.6 ns      │ 584.3 ns      │ 100     │ 3200
│  ├─ b07_transposition            17.96 ns      │ 36.12 ns      │ 17.96 ns      │ 18.29 ns      │ 100     │ 51200
│  ├─ b08_irregular_transposition  155.2 ns      │ 220.1 ns      │ 156.8 ns      │ 158.9 ns      │ 100     │ 12800
│  ├─ b09_straddling               38.86 ns      │ 60.73 ns      │ 39.25 ns      │ 39.42 ns      │ 100     │ 25600
│  ├─ b10_adfgvx                   59.95 ns      │ 95.5 ns       │ 60.73 ns      │ 61.52 ns      │ 100     │ 25600
│  ├─ b11_nihilist                 81.83 ns      │ 509.9 ns      │ 82.61 ns      │ 97.6 ns       │ 100     │ 12800
│  ├─ b12_vic                      459.1 ns      │ 643.5 ns      │ 518.5 ns      │ 505.3 ns      │ 100     │ 3200
│  ├─ b13_secom                    362.3 ns      │ 1.912 µs      │ 374.8 ns      │ 394.4 ns      │ 100     │ 800
│  ├─ b14_chaocipher               1.724 µs      │ 2.262 µs      │ 1.762 µs      │ 1.757 µs      │ 100     │ 800
│  ├─ b15_solitaire                4.599 µs      │ 7.299 µs      │ 4.899 µs      │ 4.94 µs       │ 100     │ 200
│  ╰─ b16_wheatstone               290.4 ns      │ 501.3 ns      │ 290.4 ns      │ 296.3 ns      │ 100     │ 6400
╰─ b1_decryption                                 │               │               │               │         │
   ├─ b01_caesar                   20.69 ns      │ 20.89 ns      │ 20.69 ns      │ 20.72 ns      │ 100     │ 51200
   ├─ b02_vigenere                 160.7 ns      │ 345.1 ns      │ 162.3 ns      │ 164.8 ns      │ 100     │ 6400
   ├─ b03_autokey                  210.7 ns      │ 276.3 ns      │ 213.8 ns      │ 213.8 ns      │ 100     │ 6400
   ├─ b04_autocrypt                75.19 ns      │ 281 ns        │ 87.49 ns      │ 92.66 ns      │ 100     │ 25600
   ├─ b05_square                   32.02 ns      │ 43.55 ns      │ 32.22 ns      │ 32.64 ns      │ 100     │ 51200
   ├─ b06_playfair                 53.31 ns      │ 80.26 ns      │ 53.7 ns       │ 54.68 ns      │ 100     │ 25600
   ├─ b07_transposition            26.36 ns      │ 39.44 ns      │ 26.55 ns      │ 26.95 ns      │ 100     │ 51200
   ├─ b08_irregular_transposition  240.4 ns      │ 324.8 ns      │ 241.9 ns      │ 243.7 ns      │ 100     │ 6400
   ├─ b09_straddling               63.08 ns      │ 109.1 ns      │ 63.86 ns      │ 66.02 ns      │ 100     │ 25600
   ├─ b10_adfgvx                   75.19 ns      │ 225.9 ns      │ 76.75 ns      │ 82.48 ns      │ 100     │ 25600
   ├─ b11_nihilist                 131 ns        │ 281 ns        │ 132.6 ns      │ 136 ns        │ 100     │ 6400
   ├─ b12_vic                      509.1 ns      │ 809.1 ns      │ 515.4 ns      │ 519.7 ns      │ 100     │ 3200
   ├─ b13_secom                    399.8 ns      │ 777.9 ns      │ 409.1 ns      │ 413.9 ns      │ 100     │ 3200
   ├─ b14_chaocipher               1.724 µs      │ 2.249 µs      │ 1.737 µs      │ 1.737 µs      │ 100     │ 800
   ├─ b15_solitaire                4.749 µs      │ 9.749 µs      │ 4.849 µs      │ 4.975 µs      │ 100     │ 200
   ╰─ b16_wheatstone               202.9 ns      │ 515.4 ns      │ 231 ns        │ 276.7 ns      │ 100     │ 3200
```

There is a separate benchmark for internal (aka helpers) functions:

```text
Timer precision: 100 ns
helpers                     fastest       │ slowest       │ median        │ mean          │ samples │ iters
├─ condense                               │               │               │               │         │
│  ├─ bench_condense        712.3 ns      │ 1.262 µs      │ 724.8 ns      │ 748.6 ns      │ 100     │ 1600
│  ╰─ bench_condense_str    53.71 ns      │ 70.51 ns      │ 54.1 ns       │ 54.32 ns      │ 100     │ 25600
├─ fix_double                             │               │               │               │         │
│  ├─ bench_double_aligned  206 ns        │ 329.4 ns      │ 207.6 ns      │ 226.4 ns      │ 100     │ 6400
│  ├─ bench_expand          85.74 ns      │ 182.6 ns      │ 88.09 ns      │ 117.1 ns      │ 100     │ 12800
│  ╰─ bench_fix_double      111.5 ns      │ 132.6 ns      │ 112.3 ns      │ 112.9 ns      │ 100     │ 12800
╰─ shuffle                                │               │               │               │         │
   ├─ bench_shuffle         138.8 ns      │ 228.7 ns      │ 141.9 ns      │ 142.7 ns      │ 100     │ 12800
   ╰─ bench_transp_shuffle  154.4 ns      │ 291.9 ns      │ 157.6 ns      │ 176.3 ns      │ 100     │ 6400
```

## TODO

- more ciphers ~~(Vigenère and its 2 autoclave variants incoming)~~
- ~~implement compile-time type safety through zero-sized types (ZST), see square.rs and playfair for example.~~
- improvements to the UI of the application
- more tests (and better ones!)
- better display of results
- refactoring to reduce code duplication: always in progress
- explore alternate implementations 

## Contributing

Please see CONTRIBUTING.md for some simple rules.

## Bibliography

- [The Codebreakers, 2nd Edition, David Kahn, 1996, Scribner](https://www.amazon.com/Codebreakers-Comprehensive-History-Communication-Internet-ebook/dp/B001D201IK/)
- [Kahn on Codes, David Kahn, 1984, Mcmillan](https://www.amazon.com/Kahn-Codes-Secrets-New-Cryptology/dp/0025606409/)
- [Decrypted Secrets, F. L. Bauer, 1997, Springer](https://www.amazon.com/Decrypted-Secrets-Methods-Maxims-Cryptology/dp/3540604189)
- [Cryptography, Theory and Practice, Douglas Stinson, 2018, CRC Press](https://www.amazon.com/Cryptography-Theory-Practice-Textbooks-Mathematics-ebook/dp/B07H34Q22C)

## General References

- [A Cryptographic Compendium](http://www.quadibloc.com/crypto/jscrypt.htm) - John J. G. Savard
- [Cipher Machines and Cryptology](https://www.ciphermachinesandcryptology.com/index.htm)
- [SIGABA Machine](http://www.cryptomuseum.com/crypto/usa/sigaba/index.htm)
- [Solitaire](https://www.schneier.com/academic/solitaire/) - Bruce Schneier

## Wikipedia References

- [ADFGVX](https://en.wikipedia.org/wiki/ADFGVX)
- [Autokey Cipher](https://en.wikipedia.org/wiki/Autokey_cipher)
- [Caesar cipher](https://en.wikipedia.org/wiki/Caesar_cipher)
- [Chaocipher](https://en.wikipedia.org/wiki/Chaocipher)
- [Substitution](https://en.wikipedia.org/wiki/Substitution_cipher)
- [Playfair cipher](https://en.wikipedia.org/wiki/Playfair_cipher)
- [Polybius square](https://en.wikipedia.org/wiki/Polybius_square)
- [Transposition](https://en.wikipedia.org/wiki/Transposition_(cryptography))
- [Nihilist cipher](https://en.wikipedia.org/wiki/Nihilist_cipher)
- [SECOM](http://www.ciphermachinesandcryptology.com/en/secom.htm)
- [SIGABA cipher machine](https://en.wikipedia.org/wiki/SIGABA)
- [Solitaire](https://en.wikipedia.org/wiki/Solitaire_(cipher))
- [Straddling checkerboard](https://en.wikipedia.org/wiki/Straddling_checkerboard)
- [VIC cipher](https://en.wikipedia.org/wiki/Vic-cipher)
- [Vigenère Ciphers](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher)
- [Wheatstone cipher](https://en.wikipedia.org/wiki/Wheatstone_cipher)

