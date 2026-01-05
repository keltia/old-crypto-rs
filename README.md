# old-crypto-rs — Old paper & pencil ciphers in Rust.

[![dependency status](https://deps.rs/repo/github/keltia/old-crypto-rs/status.svg)](https://deps.rs/repo/github/keltia/old-crypto-rs)
[![](https://img.shields.io/crates/v/old-crypto-rs.svg)](https://crates.io/crates/old-crypto-rs)
[![Docs](https://docs.rs/old-crypto-rs/badge.svg)](https://docs.rs/old-crypto-rs)

[![SemVer](https://img.shields.io/badge/semver-2.0.0-blue)](https://semver.org/spec/v2.0.0.html)
[![License](https://img.shields.io/badge/license-MIT-red.svg?style=flat)](https://raw.githubusercontent.com/keltia/old-crypto-rs/main/LICENSE)

`old-crypto-rs` is a [Rust](https://rust-lang.org/) port of my [cipher](https://github.com/keltia/cipher) Go package, 
which was a port of my [old-crypto](https://github.com/keltia/old-crypto) Ruby code.

Part of the conversion has been done through the AI plugin inside RustRover called Junie.

It features a simple CLI-based tool called `old-crypto` which serve both as a collection of use-cases for the library,
and an easy way to use it.

**Work in progress, still incomplete**

## Table of content

- [Features](#features)
- [Installation](#installation)
- [TODO](#todo)
- [Contributing](#contributing)

## Features

It currently implement a few of the Go/Ruby code, namely:

- Caesar (you can choose the shift number)
- Playfair
- Chaocipher
- Simple transposition (can be used with other ciphers as super-encipherement)
- Polybius square bigrammatic cipher (for ADFGVX = polybius + transposition)
- ADFGVX (6x6 square including numbers)
- Straddling Checkerboard (for the Nihilist & VIC ciphers)
- Nihilist cipher (transposition as super-encipherment)
- VIC Cipher (straddling checkerboard followed by a transposition)
- Wheatstone cipher machine

It does not try to reinvent the wheel and implements the `Block` trait, copying the Go interface for block ciphers.

## Installation

Like many Rust crates, the installation is straightforward:

    cargo install old-crypto-rs

>NOTE: the crate is not yet published on crates.io,

or

    git clone https://github.com/keltia/old-crypto-rs.git
    cd old-crypto-rs
    cargo run

The library is fetched, compiled and installed.  The `old-crypto` binary will also be installed (on windows, this will 
be called `old-crypto.exe`).

## Benchmarks & Tests

I tried to provide benchmarks for all ciphers (including key scheduling/expansion) and in some cases several implementations (and associated benchamarks).

You can run them with

    cargo test
    cargo bench

## TODO

- more ciphers
- more tests (and better ones!)
- better display of results
- refactoring to reduce code duplication: always in progress
- even more tests

## Contributing

Please see CONTRIBUTING.md for some simple rules.

## References

- [Substitution](https://en.wikipedia.org/wiki/Substitution_cipher)
- [Caesar cipher](https://en.wikipedia.org/wiki/Caesar_cipher)
- [Polybius square](https://en.wikipedia.org/wiki/Polybius_square)
- [Transposition](https://en.wikipedia.org/wiki/Transposition_(cryptography))
- [Playfair cipher](https://en.wikipedia.org/wiki/Playfair_cipher)
- [Chaocipher](https://en.wikipedia.org/wiki/Chaocipher)
- [ADFGVX](https://en.wikipedia.org/wiki/ADFGVX)
- [Nihilist cipher](https://en.wikipedia.org/wiki/Nihilist_cipher)
- [Wheatstone cipher](https://en.wikipedia.org/wiki/Wheatstone_cipher)
- [VIC cipher](https://en.wikipedia.org/wiki/Vic-cipher)
- [Straddling checkerboard](https://en.wikipedia.org/wiki/Straddling_checkerboard)
- [Vigenère cipher](https://en.wikipedia.org/wiki/Vigenère_cipher)
