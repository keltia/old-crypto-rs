# PURPLE machine model

This crate models the *cryptographic behavior* of the Japanese diplomatic
PURPLE machine (Angooki Taipu B), using recovered electrical tables. The
original Japanese machine's complete mechanical construction is not known;
this is not a claim to reconstruct every physical detail.

## Signal path

The configurable 26-letter alphabet allocates its first six letters to the
sixes switch and the other twenty letters to the twenties bank. Internally,
contacts are zero-based; published switch positions are numbered 1 through 25.

For **deciphering**, the twenties signal passes through switches #3, #2, then
#1 using the published decipher-oriented wiring tables. Enciphering uses the
inverse permutations in reverse switch order. The sixes bank consists of a
single switch and uses its inverse for enciphering.

`PurpleCore` implements a *stationary* electrical transformation. The stateful
`PurpleMachine` substitutes at the current settings and then steps after
successfully processing a character. A rejected input must not advance state.

## Switch movement

For each processed letter the sixes switch advances by one position. Exactly
one of the three twenties switches also advances, according to the configured
fast/middle/slow roles and the **pre-step** positions:

1. If sixes is at position 24 and the middle switch is at position 25,
   advance the slow switch.
2. Otherwise, if sixes is at position 25, advance the middle switch.
3. Otherwise, advance the fast switch.

All switch positions wrap from 25 to 1. The ordering above matters.

## Configuration and text

The daily alphabet is a bijection of uppercase ASCII `A`–`Z`. `twenties`
positions are given in *physical switch* order (#1, #2, #3), whereas `motion`
assigns switch identities in *speed* order (fast, middle, slow).

`Purple` starts from the configured initial settings for each call. Use
`PurpleConfig::build_machine()` for streaming. Strict text operations reject
unsupported characters rather than silently stripping whitespace or changing
historical stepping counts. CLI stdin accepts a final newline, but embedded
whitespace is not automatically removed.

The example configuration in `config/reference.yaml` illustrates a recovered
December 1941 setting; **it is not a universal PURPLE default key**.

## Verification

* Switch-table permutation and inversion tests validate all 25 positions.
* Historical tests cover the December 1941 `ZTX` → `FOV` prefix and a longer
  known plaintext/ciphertext segment.
* Independent interoperability testing uses the Python simulator's published
  `THEPURPLEMACHINEISNOWONLINE` → `OGIVTSIAAHMWMHTVIBYYJUOJFUE` vector.
* CLI integration tests check the actual executable, including error exits.

Run from the workspace root:

```sh
cargo fmt --all -- --check
cargo test -p purple --all-targets
cargo clippy -p purple --all-targets -- -D warnings
cargo test --workspace
```

## Primary references

* Wes Freeman, Geoff Sullivan, Frode Weierud, *PURPLE Revealed: Simulation and
  Computer-Aided Cryptanalysis of Angooki Taipu B*, *Cryptologia* (2003),
  especially Figures 6–10 and the worked diplomatic intercept:
  https://cryptocellar.org/pubs/purple-revealed.pdf
* Brian Neal, independent open-source Python PURPLE simulator and published
  example: https://github.com/gremmie/purple
