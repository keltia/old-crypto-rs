# Step 20 — Historical message transmission and reception

Source: Eugen Antal, Carola Dahlke, Robert Jahn, *Revealing secrets from WWII: the original German instructions of Schlüsselgerät 41*, *Cryptologia* (2025), Appendix B and §3.4.4, https://doi.org/10.1080/01611194.2025.2557311.

The transmitting station selects a new random four-letter indicator for wheels 1–4; the sender's station assignment positions wheels 5–6. The daily key selects the six pin rows, and the disguise key masks the indicator based on the first three *actual ciphertext* letters. The indicator is transmitted as ten letters (eight masked, two random filler), followed by grouped ciphertext. The operator encrypts 0–4 random letters after the plaintext to reach a multiple of five. Machine ciphertext, including padding, is limited to 600 letters; longer plaintexts require separately keyed messages.

`encipher_message` accepts explicit filler and padding, never secretly generates pseudo-random material. `decipher_message` recovers the indicator and returns **all** deciphered machine letters: ciphertext padding cannot be distinguished from real text by the recipient without out-of-band length information. Prepared German plaintext is returned in machine alphabet, not losslessly reconstructed. This module intentionally does not implement multipart messages, station directories, dates, or a CLI. Grouping uses existing shared text helpers.

The published example `KNVP / CMQ -> RIAVMDQOWT` is a *header* known-answer, not a whole-message known-answer; no independently sourced ciphertext body for the complete March 16 message is available. The tests therefore check round trips and wire structure but do not claim end-to-end archival interoperability.

The pin-row truncation rule is **confirmed** in footnote 17 of the archival paper: all 25 symbols for wheels 1–2, first 23 for wheels 3–4, and first 24 for wheels 5–6. Step 19's implementation already follows it.

Apply the patch from repository root with `git apply --check sg41-step20.patch && git apply sg41-step20.patch`, then `cargo fmt --all && cargo nextest run -p sg-41`.
