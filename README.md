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
- Fialka M-125-3, with Polish 3K and Czechoslovak 6K adjustable rotor sets
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

## Feature flags

There are two main feature flags: `fialka` and `sigaba` for the two main cipher machines implementations.

The first is for the implementation of the Russian device called , and the second one is for the ECM Mark II US machine
from WWII.  Now that the SIGABA full rewirte is done, its feature flag has been made part of the default.

The Fialka and SIGABA implementations are maintained as standalone workspace crates under `crates/fialka` and
`crates/sigaba`; this crate re-exports their public APIs when the corresponding feature is enabled.

### [Fialka](https://en.wikipedia.org/wiki/Fialka) (M-125)  

Fialka is the name of a Cold War-era Soviet cipher machine. A rotor machine, the device uses 10 rotors, each
with 30 contacts along with mechanical pins to control stepping. It also makes use of a punched card mechanism.  Both
Poland and Czechoslovakia had their own variants.

There are at least two versions known to exist, the M-125-MN and the M-125-3MN. The M-125-MN had a typewheel that could 
handle Latin and Cyrillic letters. The M-125-3MN had separate typewheels for Latin and Cyrillic. The M-125-3MN had 
three modes, single shift letters, double shift with letters and symbols, and digits only, for use with code books and 
to superencrypt numeric ciphers.

### [SIGABA](https://en.wikipedia.org/wiki/SIGABA) or ECM Mark II

The implementation interoperates with the Pekelney/Dunn reference model. The five index-rotor wirings are historical; 
the Pekelney large-rotor wirings are reference/simulator data rather than surviving wartime US large-rotor wirings.

SIGABA uses a typed configuration: five cipher rotors, five control rotors, and
five 10-contact index rotors. This is the Pekelney/Dunn reference configuration
used by the interoperability suite (`OOOOO/OOOOO/00000`):

```rust,no_run
use old_crypto_rs::{
    Sigaba, SigabaConfig, SigabaIndexPosition, SigabaIndexRotorId,
    SigabaIndexRotorSetting, SigabaLargeRotorSetting, SigabaOrientation,
    SigabaRotorId, SigabaRotorPosition, SigabaRotorSet,
};

let large = |id| SigabaLargeRotorSetting::new(
    SigabaRotorId::new(id).unwrap(),
    SigabaRotorPosition::new(14).unwrap(), // O
    SigabaOrientation::Normal,
);
let index = |id| SigabaIndexRotorSetting::new(
    SigabaIndexRotorId::new(id).unwrap(),
    SigabaIndexPosition::ZERO,
);

let config = SigabaConfig::new(
    SigabaRotorSet::PekelneyReference,
    [large(0), large(1), large(2), large(3), large(4)],
    [large(5), large(6), large(7), large(8), large(9)],
    [index(0), index(1), index(2), index(3), index(4)],
)?;
let sigaba = Sigaba::new(config);

assert_eq!(sigaba.encrypt_text("HELLO WORLD")?, "FLQGFQUEQCH");
```

The `sigaba` crate also provides `sigabactl`, which reads the complete rotor configuration from YAML:

```sh
cargo run -p sigaba --bin sigabactl -- \
  --config crates/sigaba/config/reference.yaml encrypt "HELLO WORLD"
```

## Available demo

```sh
cargo run --example demo
```

You may want to add `--features sigaba` or `fialka` for the cipher machines.

## Benchmarks & Tests

I tried to provide benchmarks for all ciphers (including key scheduling/expansion) and in some cases several
implementations.

You can run them with

    cargo nextest run (or cargo test)
    cargo bench

## Benchmarks

See [README.md](benches/README.md) file in the `benches` directory.

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
- [SIGINT Chatter](https://rijmenants.blogspot.com/) — Dirk Rijmenants
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
- [Fialka](https://en.wikipedia.org/wiki/Fialka)
- [SIGABA cipher machine](https://en.wikipedia.org/wiki/SIGABA)
- [Solitaire](https://en.wikipedia.org/wiki/Solitaire_(cipher))
- [Straddling checkerboard](https://en.wikipedia.org/wiki/Straddling_checkerboard)
- [VIC cipher](https://en.wikipedia.org/wiki/Vic-cipher)
- [Vigenère Ciphers](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher)
- [Wheatstone cipher](https://en.wikipedia.org/wiki/Wheatstone_cipher)
