# PURPLE

A Rust simulation of the Japanese PURPLE (Angooki Taipu B) diplomatic cipher machine.

This crate is part of the [`old-crypto-rs`](https://github.com/keltia/old-crypto-rs) workspace.

## Status

**Step 1 — workspace skeleton only.** The historical wiring tables, switch model,
stepping mechanism, configuration, encryption and decryption are not yet implemented.
No public cipher API is exposed at this stage.

## Development

From the repository root:

```sh
cargo test -p purple
cargo check -p purple
```

The rest of the workspace can be checked with `cargo test --workspace`.
