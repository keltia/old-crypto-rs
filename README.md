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

- more ciphers ~~(Vigenère and its 2 autoclave variants incoming)~~
- more tests (and better ones!)
- better display of results
- refactoring to reduce code duplication: always in progress

## Benchmarks

PC, AMD 7700X, 32 GB RAM, 500 GB M2 SSD, Win 11 25H2

```text
cargo bench --bench=ciphers

Timer precision: 100 ns
ciphers                        fastest       │ slowest       │ median        │ mean          │ samples │ iters
├─ decryption                                │               │               │               │         │
│  ├─ adfgvx                   69.34 ns      │ 127.9 ns      │ 97.07 ns      │ 91.48 ns      │ 100     │ 12800
│  ├─ autocrypt                65.04 ns      │ 82.23 ns      │ 65.04 ns      │ 65.54 ns      │ 100     │ 25600
│  ├─ autokey                  207.6 ns      │ 610.7 ns      │ 315.4 ns      │ 275 ns        │ 100     │ 6400
│  ├─ caesar                   20.7 ns       │ 28.91 ns      │ 20.9 ns       │ 21.01 ns      │ 100     │ 51200
│  ├─ chaocipher               1.849 µs      │ 2.387 µs      │ 1.862 µs      │ 1.874 µs      │ 100     │ 800
│  ├─ irregular_transposition  243.5 ns      │ 309.1 ns      │ 245.1 ns      │ 246.1 ns      │ 100     │ 6400
│  ├─ nihilist                 132.6 ns      │ 274 ns        │ 133.4 ns      │ 135.5 ns      │ 100     │ 12800
│  ├─ playfair                 53.71 ns      │ 113 ns        │ 54.49 ns      │ 67.23 ns      │ 100     │ 12800
│  ├─ secom                    421.6 ns      │ 559.1 ns      │ 424.8 ns      │ 428.5 ns      │ 100     │ 3200
│  ├─ solitaire                4.749 µs      │ 10.19 µs      │ 5.124 µs      │ 5.203 µs      │ 100     │ 200
│  ├─ square                   32.42 ns      │ 118.5 ns      │ 39.75 ns      │ 40.64 ns      │ 100     │ 51200
│  ├─ straddling               66.99 ns      │ 413.8 ns      │ 72.07 ns      │ 78.05 ns      │ 100     │ 25600
│  ├─ transposition            23.05 ns      │ 94.73 ns      │ 23.44 ns      │ 25.05 ns      │ 100     │ 51200
│  ├─ vic                      537.3 ns      │ 987.3 ns      │ 543.5 ns      │ 547.8 ns      │ 100     │ 3200
│  ├─ vigenere                 162.3 ns      │ 163.8 ns      │ 163.8 ns      │ 163.1 ns      │ 100     │ 6400
│  ╰─ wheatstone               191.9 ns      │ 195.1 ns      │ 193.5 ns      │ 193.2 ns      │ 100     │ 6400
╰─ encryption                                │               │               │               │         │
   ├─ adfgvx                   60.35 ns      │ 413 ns        │ 60.35 ns      │ 67.18 ns      │ 100     │ 25600
   ├─ autocrypt                60.74 ns      │ 115 ns        │ 61.13 ns      │ 62.27 ns      │ 100     │ 25600
   ├─ autokey                  131.8 ns      │ 173.2 ns      │ 132.6 ns      │ 133.6 ns      │ 100     │ 12800
   ├─ caesar                   20.7 ns       │ 212.5 ns      │ 20.9 ns       │ 24.89 ns      │ 100     │ 51200
   ├─ chaocipher               1.762 µs      │ 3.874 µs      │ 1.874 µs      │ 1.927 µs      │ 100     │ 800
   ├─ irregular_transposition  154.4 ns      │ 206 ns        │ 156 ns        │ 156.8 ns      │ 100     │ 6400
   ├─ nihilist                 88.87 ns      │ 121.6 ns      │ 89.65 ns      │ 90.37 ns      │ 100     │ 12800
   ├─ playfair                 396.6 ns      │ 765.4 ns      │ 402.9 ns      │ 409.1 ns      │ 100     │ 3200
   ├─ secom                    384.1 ns      │ 465.4 ns      │ 390.4 ns      │ 391.4 ns      │ 100     │ 3200
   ├─ solitaire                4.749 µs      │ 6.649 µs      │ 4.949 µs      │ 5.039 µs      │ 100     │ 200
   ├─ square                   32.03 ns      │ 54.49 ns      │ 32.42 ns      │ 32.92 ns      │ 100     │ 51200
   ├─ straddling               45.9 ns       │ 66.99 ns      │ 46.29 ns      │ 46.75 ns      │ 100     │ 25600
   ├─ transposition            17.58 ns      │ 29.2 ns       │ 25.1 ns       │ 21.7 ns       │ 100     │ 102400
   ├─ vic                      487.3 ns      │ 799.8 ns      │ 546.6 ns      │ 543.8 ns      │ 100     │ 3200
   ├─ vigenere                 141.9 ns      │ 1.595 µs      │ 143.5 ns      │ 207.2 ns      │ 100     │ 6400
   ╰─ wheatstone               287.3 ns      │ 457.6 ns      │ 288.8 ns      │ 290.7 ns      │ 100     │ 6400
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

