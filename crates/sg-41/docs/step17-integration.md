# SG-41 historical indicator foundations — Step 17

Source file: crates/sg-41/src/message.rs

Integrate into the current develop branch of old-crypto-rs:

1. Copy `crates/sg-41/src/message.rs` into the matching repository path.
2. Add `mod message;` in `crates/sg-41/src/lib.rs`.
3. Add these public re-exports in `lib.rs`:

   `pub use message::{DisguiseKey, MessageError, MessageIndicator, make_header, mask_indicator, unmask_header, unmask_indicator};`

4. Run `cargo fmt --all` and `cargo nextest run -p sg-41` (or `cargo test -p sg-41`).

No Cargo.toml edits are required (thiserror is already present).
No changes to Sg41Core, SG41, or the shared Block trait.

The test key is synthetic: it is not a March 1945 historical key.
The complete period disguise-key row needs verified transcription before
asserting the historical KNVP/CMQ -> RIAVMDQO known-answer test.

Validation note: Rust compiler unavailable in the execution environment;
source and test suite are provided, not claimed to have been compiled.
