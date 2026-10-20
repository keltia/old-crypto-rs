# Step 22 — Message-procedure verification and limitations

This is the final verification checkpoint for the SG-41 historical-message
extension. It distinguishes tested behavior from the historical claims that
still require a complete independently published message vector.

## Evidence levels

- **Historical indicator known-answer:**
  `tests/message_indicator_historical.rs` loads the 16 March 1945 YAML fixture
  using `noyalib`. It checks the published `KNVP`, `CMQ`,
  `RIAVMDQO` and `RIAVMDQOWT` example against the documented disguise key.
  This validates the *indicator layer*, not an entire ciphertext transmission.
- **Machine known-answer:** existing mechanical SG-41 reference tests validate
  the machine operation for their specified configurations. They do not by
  themselves validate historical message framing or a complete daily traffic key.
- **Synthetic transmission round trips:**
  `tests/message_transmission_regression.rs` and the transmission/CLI unit
  tests use synthetic monthly pin rows with historically sourced example
  values for other fields. These exercise composition, but do not establish
  an independently corroborated 1945 full-message ciphertext.

## Current API invariants (subject to local test validation)

The message layer consumes caller-provided random indicator, header filler,
and plaintext padding. The ten-character disguised header precedes the
ciphertext. The receiver uses the *sending* station's wheel settings, and
uses ciphertext positions 1–3 (wire positions 11–13) for unmasking.

The body is a multiple of five letters, with no more than 600 machine-produced
letters under the current implementation's interpretation of the historical
limit. Padding is enciphered by the moving machine, not copied onto the wire.
The original unpadded plaintext length is not recoverable from the wire alone;
`DecipheredMessage` correctly retains the trailing plaintext padding.

The March 1945 table is **not** a complete known-answer transmission: `CMQ`
is only the published ciphertext prefix used for indicator masking. Do not
assert that a synthetic pin configuration reproduces the full original message.

## Source and status

The historical basis is Antal, Dahlke and Jahn, *Revealing secrets from WWII:
the original German instructions of Schlüsselgerät 41*, *Cryptologia*,
https://doi.org/10.1080/01611194.2025.2557311, especially sections 3.4
and Appendix B. Figures 11–12 supply pin/daily/disguise table examples.

Footnote 17 specifies using 25 pin entries on wheels 1–2, the first 23 on
wheels 3–4, and the first 24 on wheels 5–6. This resolves the earlier
uncertainty about the length-25 monthly rows.

The older `docs/message-procedures.md` is a research-stage specification and
still contains language about *proposed* APIs and an *untranscribed* disguise
key. It should be reconciled against the now-implemented Steps 17–21 before
being presented as current implementation documentation. Avoid silently
rewriting historical evidence or treating illustrative fixtures as originals.

## Suggested local validation

```sh
cargo fmt --all --check
cargo nextest run -p sg-41
cargo test -p sg-41 --test message_transmission_regression
```

A future fully independent end-to-end interoperability assertion requires a
corroborated complete historical ciphertext and the corresponding monthly,
daily, station, message and disguise key material. That vector is not supplied
by the published `CMQ` indicator example alone.
