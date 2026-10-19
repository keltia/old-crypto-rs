# M-209

Historically grounded Rust simulation of the U.S. Army Hagelin **M-209** mechanical cipher machine, built within `old-crypto-rs`.

**Implementation status (Step 23):** Historical six-wheel/27-bar mechanism, independent known-answer tests, the shared `old_crypto_rs::Block` facade, strict named key lists, twelve-contact derived indicators, complete message envelopes, and `m209ctl` commands. The 1944 direct-indicator procedure and other wartime variations are not implemented.

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

## Supported message procedure and limitations

The **derived-indicator twelve-contact profile** is supported. It transmits
repeated opening and closing indicators, chooses a daily key by its two-letter
identifier, derives an internal wheel alignment, enciphers the message body,
and adds literal `X` padding *after* encryption to complete five-letter groups.
The sender knows the padding count, but **a receiver cannot reliably remove
padding** without independent message-length information. Raw decryption thus
preserves all body contacts, including those produced from trailing padding;
historical display maps decoded `Z` to spaces and is inherently lossy.

The example key ID `XA` is **illustrative**, not a verified operational wartime
assignment. The complete-message training fixture is from the
[Virtual Hagelin tutorial](https://m209.virtualcolossus.co.uk/tutorial.html),
not a claim that the 1944 manual prescribed this procedure universally.
Other wartime profiles, notably the 1944 direct-indicator procedure, the Python
24-contact fallback, and random indicator generation are **not implemented**.

For the detailed procedure and source distinctions, see
[`docs/message-procedures.md`](docs/message-procedures.md).

### Complete-message CLI example

```sh
cargo run -p m209 -- message-encrypt \
  --key-store crates/m209/config/key-list-reference.yaml \
  --key-id XA --system K --external DUFLJB \
  'OPERATION ZEBRA STARTS AT SUNSET'
# KKDUF LJBXA KBMUN ODDDC YWLVM RBVUS QYRHT XNZUI HXXXX KKDUF LJBXA

cargo run -p m209 -- message-decrypt \
  --key-store crates/m209/config/key-list-reference.yaml \
  'KKDUF LJBXA KBMUN ODDDC YWLVM RBVUS QYRHT XNZUI HXXXX KKDUF LJBXA'
```

Body-only `encrypt` and `decrypt` still accept a single `--config` YAML;
message commands instead use `--key-store`. These formats are intentionally
distinct and parsed using `noyalib`.

### Sources

- U.S. War Department, *TM 11-380: Converter M-209, M-209-A, M-209-B*, 17 March 1944, especially Tables I–II and the machine check: https://deweger.net/apparaten/downloads/M209%20manual.pdf
- Earlier War Department documents and manuals: https://radionerds.com/index.php/M-209
- Brian Neal, Python M-209 simulator and published API example: https://m209.readthedocs.io/en/latest/m209.html
- Key-list notation: https://m209.readthedocs.io/en/latest/keylist.html

## Benchmarks (Step 16)

Run `cargo bench -p m209 --bench m209` from the workspace root. The Divan
suite measures validated-key construction, machine construction, reset, frozen
contact conversion, stateful contact conversion and batches of 32, 256 and
4096 contacts, plus bounded `Block` encryption and decryption. Machine-key
parsing and fixture creation are excluded from the throughput timings. The
`stateful_convert_contacts` batch API allocates its result; `Block` uses a
reusable destination buffer and reconstructs the starting state each call.
The numbers therefore measure distinct public operations, not identical
workloads. No reported benchmark timing is claimed without running Divan.


### Named key lists (Step 19)

`KeyStore::from_yaml` loads strictly validated collections of daily keys.
Each key requires a two-uppercase-letter ID, six effective-pin sets,
exactly 27 ordered lug pairs, and a verified 26-letter check. See
[`config/key-list-reference.yaml`](config/key-list-reference.yaml) for a
historical-mechanics test fixture. The key ID in that fixture is illustrative.

Steps 20–22 add indicator derivation, message envelopes, and their CLI commands.
The original body-only key-file format remains supported.

### Derived message indicators (Step 20)

`derive_internal_indicator(&key_list, 'K', "DUFLJB")` implements the
strict twelve-contact derived-indicator procedure. It returns the intermediate
letters and the six typed secret starting positions; it does **not** construct
a complete wartime message. See `docs/message-procedures.md` for the precise
historical profile and limitations.

## Complete derived-indicator messages (Step 21)

Use `encipher_message(&KeyStore, KeyId, system, external, plaintext)` with explicit
indicators and `decipher_message(&KeyStore, transmitted)` for grouped envelopes.
The API supports the twelve-contact derived-indicator training profile, *not*
the distinct 1944 direct-indicator profile. The sender reports the number of
post-encryption `X` padding letters, but received padding is ambiguous and
is never stripped automatically. Full CLI wiring remains Step 22.

## Complete-message CLI (Step 22)

The twelve-contact derived-indicator training procedure is available through
separate `m209ctl` subcommands. The original body-only `encrypt` and `decrypt`
commands remain available with `--config` and `--mode`.

From the workspace root, run:

```sh
cargo run -p m209 -- message-encrypt \
  --key-store crates/m209/config/key-list-reference.yaml \
  --key-id XA --system K --external DUFLJB \
  'OPERATION ZEBRA STARTS AT SUNSET'

cargo run -p m209 -- message-decrypt \
  --key-store crates/m209/config/key-list-reference.yaml \
  --raw-output \
  'KKDUF LJBXA KBMUN ODDDC YWLVM RBVUS QYRHT XNZUI HXXXX KKDUF LJBXA'
```

The first command produces the published grouped message. The second deciphers
all received body contacts, **including ambiguous post-encryption padding**.
Omit `--raw-output` to display decoded `Z` as spaces; this is lossy and does
not recover literal Z characters. `--key-store` contains independently verified
named daily keys, not the single-key `--config` YAML schema. Indicators must be
supplied explicitly; no randomness or indicator generation is implied.

These commands implement the *derived-indicator training profile only*; they
must not be described as covering every historical U.S. Army procedure.
