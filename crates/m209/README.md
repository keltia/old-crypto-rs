# M-209

A Rust implementation of the U.S. Army **Hagelin M-209** mechanical cipher machine, in the `old-crypto-rs` workspace.

**Status:** Step 3 — validated contacts, wheel identities and visible positions, pin bitsets, and ordered lug pairs. No encryption/decryption implementation exists yet.

The historical specification, cited sources, known-answer fixtures and 17-step implementation plan are in [`docs/m209.md`](docs/m209.md), created in Step 1.

## Check

From the workspace root:

```sh
cargo test -p m209
cargo clippy -p m209 --all-targets -- -D warnings
```

Future work will reuse core-library helpers where practical and the canonical `old_crypto_rs::Block` trait, without defining another local trait.

## Step 5 — mechanical pin wheels

`PinWheel` and `WheelBank` model the independently advancing wheels and
their guide-arm pin sensing. The displayed wheel letters `AAAAAA` sense
`PONMLK`, and after one advancement `BBBBBB` senses `QPONML`. The
1944 example key initially activates wheels 2, 3, 4, and 6.

The drum and printable substitution are not yet implemented.
