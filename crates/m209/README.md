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

### Step 6: 27-bar drum

`LugDrum` holds all 27 ordered pairs of adjustable lugs. Given a wheel-bank
six-bit effective-wheel mask, each bar engages when either non-neutral lug
addresses an effective wheel. The bar is counted **once** even when both lugs
engage. `engaged_bar_mask()` exposes physical bar indices for tests and
`displacement()` returns the unreduced tooth count (0–27).

For the original 1944 manual's sample key, wheels 2, 3, 4 and 6 are active
at `AAAAAA`; exactly bars 1–3 and 5–21 engage, producing 20 teeth.
This is a drum fixture only, **not yet a ciphertext known-answer test**.

Step 7 adds `M209Core`, which converts a letter at fixed wheel positions using the reciprocal M-209 substitution. It never advances the wheels; stateful cycling is introduced in Step 8.


### Step 8: Stateful machine

`M209Machine` wraps `M209Core`, preserving the initial state for `reset()`.
Each `convert_contact` converts using the current wheel positions and **then**
advances all six wheels once. `convert_contacts` supports streaming slices
without implicit resets. At the 1944 sample key's `AAAAAA` starting state,
the first `A` converts to `T` and the visible wheels then read `BBBBBB`.

The full 26-character historical verification string remains a Step 9 test;
message formatting, indicators and the shared `Block` adapter are later stages.

### Step 9: Original 1944 full-machine check

`tests/historical_1944.rs` exercises the original War Department TM 11-380
Table I and Table II setup (visible wheels `AAAAAA`), converting 26 `A`s
into the literal published check `TNJUWAUQTKCZKNUTOTBCWARMIO`.
The integration tests also verify reciprocal decipherment, streaming, reset,
and the wheel positions after 26 steps. This is a historical key fixture,
not a factory-fixed key. The Python interoperability fixture is Step 10.

### Step 10 — Independent interoperability vector

`tests/python_interoperability.rs` checks Brian Neal's separately published
Python M-209 example at `FFEGJP`, including the exact ciphertext, raw
decipherment, chunked processing, and reset. It expands the ten specified lug
pairs to 27 physical bars by filling the remaining seventeen with neutral
`0-0` pairs; see the [published key-list notation](https://m209.readthedocs.io/en/latest/keylist.html).

Space-to-`Z` conversion and five-letter grouping are expressed explicitly in
the test. The historical text-handling API is deferred to Step 13.
