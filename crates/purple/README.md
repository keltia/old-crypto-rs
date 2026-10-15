# PURPLE

A typed Rust simulation of the Japanese diplomatic PURPLE (Angooki Taipu B) cipher machine.
Part of the [`old-crypto-rs`](https://github.com/keltia/old-crypto-rs) workspace.

## Use as a Rust library

```rust
use purple::{Purple, PurpleAlphabet, PurpleConfig, PurpleMotion, SwitchPosition, TwentiesSwitchId};

let pos = |n| SwitchPosition::new(n).unwrap();
let config = PurpleConfig::new(
    PurpleAlphabet::new("NOKTYUXEQLHBRMPDICJASVWGZF").unwrap(),
    pos(9),
    [pos(1), pos(24), pos(6)],
    PurpleMotion::new(TwentiesSwitchId::Two, TwentiesSwitchId::Three, TwentiesSwitchId::One).unwrap(),
);
let purple = Purple::new(config);
assert_eq!(
    purple.encrypt_text("THEPURPLEMACHINEISNOWONLINE").unwrap(),
    "OGIVTSIAAHMWMHTVIBYYJUOJFUE"
);
```

`Purple` is reset-per-call. Use `PurpleConfig::build_machine()` for a continuous,
stateful message stream. The crate imports the shared `old_crypto_rs::Block`
trait rather than defining its own compatibility trait.

## CLI (`purplectl`)

The command interface follows `sigabactl` and `kl7ctl`, using `clap`
subcommands and optional YAML key sheets. Input comes from positional
`TEXT` arguments or standard input when no text is supplied. Text is strict
uppercase ASCII; spaces and punctuation are not silently removed.

```sh
cargo run -p purple --bin purplectl -- encrypt THEPURPLEMACHINEISNOWONLINE
cargo run -p purple --bin purplectl -- decrypt OGIVTSIAAHMWMHTVIBYYJUOJFUE
cargo run -p purple --bin purplectl -- --config crates/purple/config/reference.yaml encrypt HELLO
printf 'THEPURPLEMACHINEISNOWONLINE\n' | cargo run -p purple --bin purplectl -- encrypt
```

The optional `--config FILE` takes YAML with `alphabet` (26 distinct
uppercase letters), `sixes` (1–25), `twenties` (three positions, physical
switch order 1–3), and `motion` (fast/middle/slow switch identities).
See `config/reference.yaml`. Without `--config`, that reference setup is used.

Use `purplectl --help` and `purplectl encrypt --help` for argument details.

## Testing

The CLI integration tests run the compiled `purplectl` executable (no network or Python required).


```sh
cargo test -p purple --all-targets
cargo clippy -p purple --all-targets -- -D warnings
cargo test --workspace
```

Historical references:

- Wes Freeman, Geoff Sullivan, Frode Weierud, *PURPLE Revealed: Simulation
  and Computer-Aided Cryptanalysis of Angooki Taipu B*, Cryptologia (2003):
  https://cryptocellar.org/pubs/purple-revealed.pdf
- Brian Neal's independent Python simulator and worked README vector:
  https://github.com/gremmie/purple

## Machine architecture and historical sources

See [docs/purple.md](docs/purple.md) for the signal path, switch motion,
historical wiring provenance, testing approach, and usage limitations.
