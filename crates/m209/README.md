# M-209

Historically grounded Rust simulation of the U.S. Army Hagelin **M-209** mechanical cipher machine, built within `old-crypto-rs`.

**Implementation status (Step 15):** Six pin wheels, 27-bar lug drum, frozen and stateful machine, verified 1944 and independent Python known-answer tests, validated key configuration, shared `old_crypto_rs::Block` facade, historical text conventions, and the `m209ctl` CLI. **Wartime message envelopes and indicator/key-list procedures are not implemented.**

The [technical specification](docs/m209.md) records the original sources, fixture provenance, mechanical conventions, implementation plan, and verification boundaries.

## Building and checking

From the workspace root:

```sh
cargo fmt --all --check
cargo test -p m209 --all-targets
cargo clippy -p m209 --all-targets -- -D warnings
```

## Command-line usage

The included [`config/reference.yaml`](config/reference.yaml) is the *example key* from U.S. War Department TM 11-380 (1944), **not a universal M-209 key**. A CLI invocation requires `--config` and starts from the indicators supplied in that file.

```sh
# Historical check string, ungrouped (26 letters)
cargo run -p m209 -- --config crates/m209/config/reference.yaml --mode raw encrypt AAAAAAAAAAAAAAAAAAAAAAAAAA
# TNJUWAUQTKCZKNUTOTBCWARMIO

# Reciprocal raw conversion
cargo run -p m209 -- --config crates/m209/config/reference.yaml --mode raw decrypt TNJUWAUQTKCZKNUTOTBCWARMIO
# AAAAAAAAAAAAAAAAAAAAAAAAAA

# Grouped text-mode output (without padding)
cargo run -p m209 -- --config crates/m209/config/reference.yaml encrypt --grouped AAAAAAAAAAAAAAAAAAAAAAAAAA
# TNJUW AUQTK CZKNU TOTBC WARMI O
```

`--grouped` never pads the final group.

Input can also be read from standard input when the text argument is omitted. In `--mode raw`, only ASCII letters are accepted; letters are normalized to uppercase. In `--mode text` (the default), plaintext spaces become machine `Z`, and displayed decrypted `Z` becomes a space. Because the letter `Z` and a word-space share the same raw contact, display decoding can be lossy. Use `decrypt --raw-output` to preserve the raw contacts. Grouping spaces in ciphertext are ignored only in text mode.

## YAML key format

`pins` contains six wheel-specific effective-pin strings in physical wheel order, `indicators` contains six initial window letters, and `lugs` contains **exactly 27** ordered `[left, right]` pairs. A lug value from 1 to 6 addresses a wheel; 0 is neutral. The parser rejects missing or extra bars, invalid lug values, invalid pin letters, incorrect indicators, and unknown YAML fields.

The CLI uses `noyalib` and Serde for YAML parsing; the mechanical key is validated by the existing typed `M209Config` constructors. No general-purpose wheel or validation implementation is duplicated in the CLI.

## Library usage

`M209Config::from_letters` constructs a validated key. Use `config.build_machine()` for **continuous stateful contact processing** (`M209Machine`), or `M209::new(config)` for the canonical `old_crypto_rs::Block` interface. The `Block` adapter begins each call at its configured initial state, writes no more than `min(src.len(), dst.len())`, and passes unsupported bytes through *without advancing* the wheels.

Historical string operations (`encrypt_text`, `decrypt_text_raw`, and `decrypt_text`) are distinct from raw contact processing and the `Block` adapter. Grouping delegates to the existing `old_crypto_rs::helpers::output_as_block` implementation.

## Independent verification

| Reference | Initial indicators | Input | Expected output |
| --- | --- | --- | --- |
| TM 11-380 (1944), Tables I–II | `AAAAAA` | `AAAAAAAAAAAAAAAAAAAAAAAAAA` | `TNJUWAUQTKCZKNUTOTBCWARMIO` |
| [Brian Neal Python M-209 example](https://m209.readthedocs.io/en/latest/m209.html) | `FFEGJP` | `THEZPIZZAZHASZARRIVED` | `QBCHUWCCDIYFNCHLOZJYG` |

The Rust tests exercise encryption, reciprocal decipherment, streaming, reset, wheel advancement, and key validation. The published references fix the expected ciphertext independently of the implementation under test.

## Scope and next stages

This is a **cipher machine and message-body simulator**, not a complete implementation of historical operating procedures. Do not treat `m209ctl` output as a historically framed military message: external/internal indicators, key lists, procedure-specific padding, and message headers are not generated or checked. The remaining planned work is Step 16 (Divan benchmarks) and Step 17 (demo, TUI, root README, and workspace integration). Any later wartime message-procedure implementation should have its own separately verified fixtures and tests.

### Sources

- U.S. War Department, *TM 11-380: Converter M-209, M-209-A, M-209-B*, 17 March 1944, especially Tables I–II and the machine check: https://deweger.net/apparaten/downloads/M209%20manual.pdf
- Earlier War Department documents and manuals: https://radionerds.com/index.php/M-209
- Brian Neal, Python M-209 simulator and published API example: https://m209.readthedocs.io/en/latest/m209.html
- Key-list notation: https://m209.readthedocs.io/en/latest/keylist.html
