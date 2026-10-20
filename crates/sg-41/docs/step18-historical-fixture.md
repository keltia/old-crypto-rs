# Step 18 — historical indicator known-answer fixture

Status: **historical table transcribed and algorithm independently checked**.
Rust integration test supplied but not executed in this environment.

## Provenance

Eugen Antal, Carola Dahlke and Robert Jahn, “Revealing secrets from WWII:
the original German instructions of Schlüsselgerät 41,” *Cryptologia*,
https://doi.org/10.1080/01611194.2025.2557311.

The 16 March 1945 disguise alphabet and numeric row are transcribed from the
user-supplied image labeled Figure 12, from its bottom row `1. 16.`.
The adjacent *Tagesschlüssel* is `ACHUKW`. These are independent inputs to the
worked-example indicator `KNVP` and ciphertext prefix `CMQ`.

| Item | Historical value |
| --- | --- |
| Disguise alphabet | `SYIZBJEHOCKUGPDRVFTXLNMWAQ` |
| Digit sequence | `96585138157834794289563262` |
| Daily key | `ACHUKW` |
| Indicator | `KNVP` |
| Ciphertext prefix | `CMQ` |
| Digit shifts (first eight) | `57832629` |
| Masked indicator | `RIAVMDQO` |
| Two-letter filler | `WT` |
| Full header | `RIAVMDQOWT` |

The first three ciphertext letters have 1-based positions C=10, M=23, Q=26
in the disguise alphabet. Their digit triples are `578`, `326`, `296`
(the Q lookup wraps from position 26 to position 1 and 2). The ninth digit
is discarded to obtain `57832629`.

The eight letters to mask are `KNVPLOWQ` (the original indicator followed by
ordinary-alphabet successors). Look up each letter in the *disguise* alphabet,
advance by the corresponding digit modulo 26, and read the resulting letters.
This independently gives `RIAVMDQO`. Inverse rotation recovers `KNVPLOWQ`;
its second half passes the successor redundancy check.

## Implementation

- `tests/fixtures/message-1945-03-16.yaml` is the historical key and expected vector.
- `tests/message_indicator_historical.rs` parses it with existing `noyalib`
  and exercises the existing `sg_41` public indicator API in both directions.
- No `src/`, `Cargo.toml`, or public API changes are needed.

Run `cargo fmt --all --check` and `cargo nextest run -p sg-41` locally.

This is an **indicator-procedure** known-answer test, not a known-answer test
of the complete mechanical encryption of a message.
