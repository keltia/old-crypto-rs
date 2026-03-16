# old-crypto-rs — Old paper & pencil ciphers in Rust.

[![dependency status](https://deps.rs/repo/github/keltia/old-crypto-rs/status.svg)](https://deps.rs/repo/github/keltia/old-crypto-rs)
[![](https://img.shields.io/crates/v/old-crypto-rs.svg)](https://crates.io/crates/old-crypto-rs)
[![Docs](https://docs.rs/old-crypto-rs/badge.svg)](https://docs.rs/old-crypto-rs)
[![GitHub release](https://img.shields.io/github/release/keltia/old-crypto-rs.svg)](https://github.com/keltia/old-crypto-rs/releases/)

[![SemVer](https://img.shields.io/badge/semver-2.0.0-blue)](https://semver.org/spec/v2.0.0.html)
[![License](https://img.shields.io/badge/license-MIT-red.svg?style=flat)](https://raw.githubusercontent.com/keltia/old-crypto-rs/main/LICENSE)

`old-crypto-rs` is a [Rust](https://rust-lang.org/) port of my [cipher](https://github.com/keltia/cipher) Go package,
which was a port of my [old-crypto](https://github.com/keltia/old-crypto) Ruby code.

Part of the conversion has been done through the AI plugin inside RustRover called Junie.

It features a simple CLI-based tool called `old-crypto` which serve both as a collection of use-cases for the library,
and an easy way to use it.  It now uses [ratatui](https://crates.io/crates/ratatui) to provide an interactive
TUI.  Key bindings and the whole UI are still a work in progress, my first TUI program, in fact.

**Work in progress, still incomplete**

## Table of content

- [Features](#features)
- [Installation](#installation)
- [TODO](#todo)
- [Contributing](#contributing)

## Features

It currently implements a few more compared to the Go/Ruby code, namely:

- Caesar (you can choose the shift number)
- Vigenère and its 2 autoclave variants (WIP)
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
all ciphers; it also check that you can decrypt back to the original plaintext.

    cargo run --example demo

There will also be a TUI tool called `old-crypto` which can be used to encrypt/decrypt text.

To run the TUI:

    cargo run --bin old-crypto

## Benchmarks & Tests

I tried to provide benchmarks for all ciphers (including key scheduling/expansion) and in some cases several
implementations.

You can run them with

    cargo nextest run
    cargo bench

## TODO

- more ciphers (Vigenère and its 2 autoclave variants incoming)
- more tests (and better ones!)
- better display of results
- refactoring to reduce code duplication: always in progress

## Benchmarks

Mac Studio 2023, M1Max, 64 GBn 4 TB NVMe SSD.

```text
cargo bench --bench=ciphers

Timer precision: 41 ns
ciphers                        fastest       │ slowest       │ median        │ mean          │ samples │ iters
├─ decryption                                │               │               │               │         │
│  ├─ adfgvx                   102.5 ns      │ 105.8 ns      │ 103.1 ns      │ 103.6 ns      │ 100     │ 6400
│  ├─ caesar                   25.87 ns      │ 26.85 ns      │ 26.2 ns       │ 26.18 ns      │ 100     │ 25600
│  ├─ chaocipher               2.957 µs      │ 10.79 µs      │ 2.999 µs      │ 3.153 µs      │ 100     │ 100
│  ├─ irregular_transposition  327.8 ns      │ 494.4 ns      │ 333 ns        │ 337.6 ns      │ 100     │ 1600
│  ├─ nihilist                 189.8 ns      │ 325.1 ns      │ 194.9 ns      │ 196.9 ns      │ 100     │ 1600
│  ├─ playfair                 68.03 ns      │ 69.34 ns      │ 68.69 ns      │ 68.62 ns      │ 100     │ 6400
│  ├─ secom                    588.1 ns      │ 1.332 µs      │ 598.6 ns      │ 616.9 ns      │ 100     │ 800
│  ├─ square                   42.96 ns      │ 43.94 ns      │ 43.29 ns      │ 43.34 ns      │ 100     │ 12800
│  ├─ straddling               86.25 ns      │ 89.51 ns      │ 86.92 ns      │ 87.22 ns      │ 100     │ 6400
│  ├─ transposition            36.13 ns      │ 37.11 ns      │ 36.78 ns      │ 36.65 ns      │ 100     │ 12800
│  ├─ vic                      645.4 ns      │ 671.5 ns      │ 650.6 ns      │ 651 ns        │ 100     │ 800
│  ├─ vigenere                 202.8 ns      │ 572.6 ns      │ 208 ns        │ 213.8 ns      │ 100     │ 800
│  ╰─ wheatstone               293.9 ns      │ 356.4 ns      │ 299.1 ns      │ 301.3 ns      │ 100     │ 1600
╰─ encryption                                │               │               │               │         │
   ├─ adfgvx                   95.37 ns      │ 97.98 ns      │ 96.67 ns      │ 96.43 ns      │ 100     │ 6400
   ├─ caesar                   25.87 ns      │ 26.69 ns      │ 26.04 ns      │ 26.14 ns      │ 100     │ 25600
   ├─ chaocipher               2.957 µs      │ 5.541 µs      │ 3.04 µs       │ 3.063 µs      │ 100     │ 100
   ├─ irregular_transposition  222.3 ns      │ 299.1 ns      │ 228.1 ns      │ 227.6 ns      │ 100     │ 3200
   ├─ nihilist                 127.2 ns      │ 129.8 ns      │ 128.5 ns      │ 128.4 ns      │ 100     │ 3200
   ├─ playfair                 489.4 ns      │ 1.114 µs      │ 499.6 ns      │ 509.9 ns      │ 100     │ 400
   ├─ secom                    525.6 ns      │ 541.4 ns      │ 530.9 ns      │ 533.6 ns      │ 100     │ 800
   ├─ square                   45.25 ns      │ 46.22 ns      │ 45.89 ns      │ 45.79 ns      │ 100     │ 12800
   ├─ straddling               60.54 ns      │ 62.17 ns      │ 60.87 ns      │ 61.11 ns      │ 100     │ 12800
   ├─ transposition            33.52 ns      │ 34.5 ns       │ 34.17 ns      │ 34.02 ns      │ 100     │ 12800
   ├─ vic                      614.1 ns      │ 1.135 µs      │ 666.4 ns      │ 687.8 ns      │ 100     │ 400
   ├─ vigenere                 198.8 ns      │ 206.7 ns      │ 201.5 ns      │ 201.9 ns      │ 100     │ 3200
   ╰─ wheatstone               452.8 ns      │ 468.4 ns      │ 457.9 ns      │ 458 ns        │ 100     │ 1600
```

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

