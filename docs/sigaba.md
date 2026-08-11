# SIGABA CSP-889 implementation specification

**Project:** `old-crypto-rs`  
**Target:** historically accurate SIGABA / ECM Mark II / CSP-889 simulator  
**Status:** implementation specification — Step 1  
**Date:** 2026-08-11

This document freezes the coordinate systems, slot numbering, rotor orientation,
stepping rules, signal-routing conventions, text handling, and validation
requirements for replacing the current `src/sigaba.rs` implementation.

The initial target is the wartime **CSP-889 / ECM Mark II / M-134-C** machine.
The later CSP-2900 variant is explicitly out of scope until the CSP-889 model is
validated against independent references.

---

## 1. Scope

The first correct implementation shall model:

- five 26-contact **cipher rotors**;
- five 26-contact **control rotors**;
- five 10-contact **index rotors**;
- interchangeability of the ten large 26-contact rotors between the cipher and
  control banks;
- direct/reversed insertion of the large rotors;
- fixed index-rotor positions;
- the CSP-889 four-signal control maze;
- control-output banding into nine index inputs;
- the five 10-contact index permutations;
- paired index outputs driving the five cipher stepping magnets;
- orientation-sensitive cipher/control rotor motion;
- encipher and decipher traversal through the cipher bank;
- SIGABA's `Z` / SPACE convention;
- complete key validation;
- reset-per-message `Block` compatibility as an adapter, not as the native
  machine model.

The following are not part of the first implementation milestone:

- CSP-2900;
- CCM Mark 1 interoperability;
- key-list/indicator operating procedure;
- printer grouping mechanics;
- numerical printing in plaintext mode;
- electrical timing at relay/solenoid level;
- physical zeroize mechanics.

---

## 2. Source precedence

Use the following source order when facts differ.

1. **NSA declassified "History of Converter M-134-C"** for physical/mechanical
   machine behavior.
2. **CSP-1100(C) / surviving ECM Mark II operating documentation** for operator
   behavior and text conventions.
3. **Crypto Museum / USS Pampanito ECM Mark II documentation** for curated
   machine descriptions.
4. **Published academic SIGABA cryptanalysis papers** for exact CSP-889
   permutation/banding models.
5. Simulator implementations only as secondary cross-checks, never as the sole
   source of a wiring table.

Where uncertainty remains, leave an explicit verification item rather than
choosing a plausible convention.

---

## 3. Machine variants

The implementation shall initially expose only:

```rust
enum SigabaVariant {
    Csp889,
}
```

Do not silently fold CSP-2900 behavior into CSP-889.

The later CSP-2900 differs in control/stepping details, including six active
control inputs rather than four and altered cipher-rotor stepping behavior.
Those differences belong in a distinct future variant.

---

## 4. Rotor banks and physical slots

SIGABA has three banks:

```text
Cipher bank   : 5 large 26-contact rotors
Control bank  : 5 large 26-contact rotors
Index bank    : 5 small 10-contact rotors
```

The ten large rotors are interchangeable between cipher and control banks.
Therefore a valid key must partition the ten large rotor identities into two
disjoint sets of five.

### 4.1 Slot numbering

Use historical left-to-right slot numbering within each bank:

```text
slot 1  slot 2  slot 3  slot 4  slot 5
LEFT                                  RIGHT
```

The Rust implementation should make bank and slot explicit:

```rust
struct LargeRotorId(u8);   // 0..9
struct CipherSlot(u8);     // 0..4
struct ControlSlot(u8);    // 0..4
struct IndexRotorId(u8);   // 0..4
struct IndexSlot(u8);      // 0..4
```

Do not use naked `usize` values for public configuration.

---

## 5. Large 26-contact rotors

The cipher and control banks use the same family of ten 26-contact rotors.

Each large rotor has:

- a fixed 26-way electrical permutation;
- an angular position A..Z;
- one of two physical insertion orientations:
  - `Normal`
  - `Reversed`

Suggested abstraction:

```rust
struct AlphabetRotor {
    wiring: Permutation<26>,
    position: Position26,
    orientation: Orientation,
}
```

### 5.1 Contact coordinates

Internally use:

```text
A = 0
B = 1
...
Z = 25
```

with a checked `Contact26`.

Do not use ASCII arithmetic inside the electrical core.

### 5.2 Electrical reversal

A reversed SIGABA rotor is physically turned around.

Do **not** define reversal merely as `Permutation::inverse()`.

Physical reversal changes:

- the direction through which the wiring is traversed;
- the visible coordinate frame;
- stepping direction;
- turnover behavior of metered control rotors.

The exact normal/reversed coordinate transforms must be fixed by published
rotor examples or an independently verified simulator before implementation
Step 3 is accepted.

---

## 6. Index rotors

Index rotors are fundamentally different devices.

They have:

- exactly 10 electrical contacts;
- positions `0..9`;
- no automatic movement during message processing.

Represent them separately:

```rust
struct IndexRotor {
    wiring: Permutation<10>,
    position: Position10,
}
```

Do **not** reuse a 26-contact rotor structure.

The standard CSP-889 model shall initially treat index rotors as installed in
their normal orientation only unless a primary source shows that reversed
index-wheel insertion was operational key material.

---

## 7. Cipher-bank electrical traversal

SIGABA has no reflector.

Enciphering passes through the five cipher rotors in one direction; deciphering
uses the inverse path in the opposite direction.

The code should make physical/electrical direction explicit rather than relying
on array iteration order:

```rust
fn encipher_contact(&self, input: Contact26) -> Contact26;
fn decipher_contact(&self, input: Contact26) -> Contact26;
```

Before stepping is added, exhaustive tests must prove:

```text
decipher(encipher(x)) == x
```

for all 26 contacts at multiple rotor configurations.

This is necessary but not sufficient evidence of historical correctness.

---

## 8. Control-bank input signals

For the CSP-889 model, four inputs to the control bank are energized for each
character.

The standard cryptanalytic model uses:

```text
F, G, H, I
```

simultaneously.

In zero-based contacts:

```text
F = 5
G = 6
H = 7
I = 8
```

These four signals pass simultaneously through the full five-rotor control
bank.

The resulting four output letters may collapse into fewer than four active
index inputs because of fixed output banding.

---

## 9. Control rotor stepping

Only control-bank slots 2, 3, and 4 move automatically.

Historical CSP-889 metering:

```text
control slot 3 : fast
control slot 4 : medium
control slot 2 : slow

control slots 1 and 5 : stationary
```

The fast rotor advances once per processed character.

The medium rotor advances once per complete revolution of the fast rotor.

The slow rotor advances once per complete revolution of the medium rotor.

Conceptually:

```text
slot 3 : every character
slot 4 : 1 per 26 slot-3 steps
slot 2 : 1 per 26 slot-4 steps
```

Do not implement this using arbitrary visible-position constants such as
`position == 13`.

### 9.1 Orientation-sensitive stepping

A reversed large rotor advances in the opposite visible alphabetic direction.

Therefore stepping belongs to the mounted rotor:

```rust
fn step(&mut self)
```

and must account for `Orientation`.

The exact rollover convention must reproduce published examples such as the
reported normal/reversed transition around the `O` reference position.

### 9.2 Step timing

The precise order:

```text
electrical processing
then stepping

or

stepping
then electrical processing
```

must be established from CSP-889 documentation or a known-answer vector before
the stateful machine API is finalized.

Do not infer this from Enigma or from the current `sigaba.rs`.

---

## 10. Control-output banding

The 26 outputs of the control bank are hard-wired into nine groups that drive
nine of the ten index-bank inputs.

The accepted CSP-889 banding is:

```text
control output   index input
B                1
C                2
D, E             3
F, G, H          4
I, J, K          5
L, M, N, O       6
P, Q, R, S, T    7
U, V, W, X, Y, Z 8
A                9
```

Index input `0` is dead/inactive.

Equivalently:

```rust
fn control_output_to_index_input(c: Contact26) -> IndexContact {
    match c {
        B       => 1,
        C       => 2,
        D | E   => 3,
        F | G | H => 4,
        I | J | K => 5,
        L | M | N | O => 6,
        P | Q | R | S | T => 7,
        U | V | W | X | Y | Z => 8,
        A       => 9,
    }
}
```

Never use arithmetic such as `(letter - 'A') % 10`.

Multiple energized control outputs landing in the same band result in one
energized index input.

Thus the index bank receives a set of 1..4 active inputs.

---

## 11. Index-bank traversal

Each active index input passes through all five stationary 10-contact index
rotors.

If the set of energized inputs is:

```text
{i1, i2, ...}
```

the five-rotor index permutation maps them independently to a set of outputs.

Duplicate outputs collapse electrically.

Use a bitset or boolean set rather than a vector with duplicates:

```rust
struct IndexSignals(u16); // only low 10 bits used
```

---

## 12. Index-output to cipher-step grouping

The ten index outputs are permanently paired into five cipher-rotor stepping
circuits.

Use the CSP-889 pairing:

```text
index outputs    cipher rotor
0, 9             1
7, 8             2
5, 6             3
3, 4             4
1, 2             5
```

In zero-based cipher-slot indexing this is:

```text
0/9 -> slot 0
7/8 -> slot 1
5/6 -> slot 2
3/4 -> slot 3
1/2 -> slot 4
```

If either member of a pair is energized, that cipher rotor steps once.

If both are energized, the rotor still steps only once.

One to four cipher rotors normally step on a character in CSP-889.

Do not derive the cipher rotor by `% 5`.

---

## 13. Cipher rotor stepping

The index bank determines which cipher rotors advance.

For each selected rotor:

```rust
cipher_rotor.step();
```

must honor that rotor's normal/reversed orientation.

The stepping operation must be represented separately from the cipher electrical
transformation so that it can be tested as a state machine.

---

## 14. Per-character machine cycle

The final cycle order is intentionally not frozen until the step-timing item is
verified.

Structurally, one character cycle contains:

```text
A. text input normalization
B. cipher-bank electrical transform
C. control-bank four-signal transform
D. control-output banding
E. index-bank transform
F. derive cipher rotors to step
G. step selected cipher rotors
H. meter control rotors
I. output character normalization
```

The exact ordering of B versus G/H must be locked by an external vector.

Index rotors never step during this cycle.

---

## 15. Text conventions

SIGABA does not transparently encode ordinary A-Z plus spaces.

Historical operating behavior:

### Encipher

```text
plaintext Z     -> X entering the cipher maze
plaintext SPACE -> Z entering the cipher maze
```

### Decipher

```text
decrypted Z -> SPACE
```

Thus plaintext `Z` is intentionally lossy and is represented as `X`.

A message such as:

```text
ZERO
```

is effectively processed as:

```text
XERO
```

at the cipher-maze input.

The native electrical core should still process pure `Contact26` values.
Text conversion belongs in a presentation layer.

---

## 16. Key model

A complete CSP-889 cryptographic configuration must contain:

```rust
struct SigabaConfig {
    cipher: [MountedLargeRotor; 5],
    control: [MountedLargeRotor; 5],
    index: [MountedIndexRotor; 5],
}
```

Configuration must validate:

### Large rotors

Across cipher + control banks:

```text
all ten large rotor identities appear exactly once
```

No duplicate large rotor may appear, and none may be omitted.

Each large rotor specifies:

```text
identity
orientation
initial A..Z position
```

### Index rotors

All five index rotor identities appear exactly once.

Each index rotor specifies:

```text
identity
initial 0..9 position
```

Index position validation is `0..9`, never `0..25`.

---

## 17. Native stateful API

Do not design SIGABA around `Block`.

Preferred internal/public model:

```rust
struct SigabaMachine {
    config: ...
    state: ...
}

impl SigabaMachine {
    fn encipher_contact(&mut self, input: Contact26) -> Contact26;
    fn decipher_contact(&mut self, input: Contact26) -> Contact26;

    fn positions(&self) -> SigabaPositions;
    fn reset(&mut self);
}
```

A higher-level `Sigaba` value can retain immutable configuration and construct a
fresh `SigabaMachine` for each `Block::encrypt()`/`decrypt()` call, matching the
pattern now used for Fialka.

Avoid `RefCell` unless there is a compelling reason.

---

## 18. `Block` adapter semantics

The `Block` adapter should:

- reset to configured state for each call;
- process at most `min(src.len(), dst.len())`;
- never panic on a short destination;
- define clearly whether its bytes represent:
  - raw contacts `0..25`, or
  - normalized ASCII text.

Given the rest of `old-crypto-rs`, a separate text API plus raw-contact `Block`
adapter is preferable.

---

## 19. Rotor wiring data

The current `sigaba.rs` rotor constants must not be trusted automatically.

Before implementation:

1. transcribe the ten published 26-contact rotor permutations from an
   authoritative source;
2. transcribe the five published 10-contact index permutations;
3. validate every table as a bijection;
4. store source-oriented fixtures so transcription can be audited;
5. compare at least selected entries with a second source.

Do not preserve current strings merely for compatibility.

---

## 20. Test hierarchy

A correct implementation requires multiple layers.

### 20.1 Permutation tests

For all 15 rotor wirings:

- correct range;
- every output occurs exactly once;
- inverse is exact.

### 20.2 Large-rotor electrical tests

For each of the ten large rotors:

- normal orientation at multiple positions;
- reversed orientation at multiple positions;
- right/left inversion over all 26 contacts.

### 20.3 Index-rotor tests

For all five index rotors:

```text
10 inputs × 10 positions × both traversal directions
```

as applicable to the fixed bank coordinate model.

### 20.4 Control banding tests

Explicitly assert:

```text
B -> 1
C -> 2
DE -> 3
FGH -> 4
IJK -> 5
LMNO -> 6
PQRST -> 7
UVWXYZ -> 8
A -> 9
```

and verify index input 0 is never generated.

### 20.5 Index pairing tests

Explicitly assert:

```text
0/9 -> cipher slot 1
7/8 -> cipher slot 2
5/6 -> cipher slot 3
3/4 -> cipher slot 4
1/2 -> cipher slot 5
```

### 20.6 Control metering tests

Starting from a known position:

- slot 3 moves every character;
- slots 1 and 5 never move;
- slot 4 moves after 26 fast steps;
- slot 2 moves after 26 medium revolutions;
- normal and reversed slot-2/3/4 rotors move in opposite visible directions.

### 20.7 Cipher stepping tests

Given a controlled set of energized index outputs, verify exactly which cipher
rotors step and that duplicates do not double-step a rotor.

### 20.8 Frozen cipher-bank tests

With stepping disabled, exhaustively verify that encipher and decipher are
inverse for all 26 contacts.

### 20.9 Text convention tests

Verify:

```text
SPACE enciphers as electrical Z
plaintext Z enciphers as electrical X
decrypted electrical Z prints SPACE
```

### 20.10 Known-answer tests

At least one complete externally sourced vector is required:

```text
variant = CSP-889
cipher rotor order
cipher rotor orientations
cipher initial positions
control rotor order
control rotor orientations
control initial positions
index rotor order
index positions
plaintext
ciphertext
```

Round-trip tests are not sufficient.

A useful published plaintext/ciphertext pair exists:

```text
ZERO ONE TWO THREE FOUR FIVE SIX
IEQDEMOKGJEYGOKWBXAIPKRHWARZODWG
```

but it must not be added as a machine KAT until its complete associated key is
recovered from the source.

The historical operating manuals also describe "26-30" check strings: after
zeroizing and processing 25 characters, encrypting `AAAAA` must match the
published daily check string. Such check strings are excellent KATs when a
complete key-list entry is available.

---

## 21. Current `sigaba.rs` behaviors that must be removed

The replacement implementation must not retain these current shortcuts:

```text
index rotors stored as 26-contact rotors
index position range 0..25
control output mapped with `% 10`
index output mapped with `% 5`
arbitrary `position == 13` control stepping
same large rotor allowed in both cipher and control banks
generic ASCII arithmetic in rotor core
unbounded writes to `dst[i]`
round-trip-only correctness tests
```

These are implementation defects, not compatibility requirements.

---

## 22. Proposed module structure

Replace the monolithic `src/sigaba.rs` with:

```text
src/sigaba/
├── mod.rs
├── contact.rs
├── permutation.rs
├── alphabet_rotor.rs
├── index_rotor.rs
├── control.rs
├── stepping.rs
├── machine.rs
├── config.rs
├── text.rs
└── data.rs
```

Possible later split:

```text
data/
├── mod.rs
├── large_rotors.rs
└── index_rotors.rs
```

Reuse Fialka's generic `Permutation<N>` only if extracting it into a genuinely
machine-independent internal module makes the code cleaner. Do not couple SIGABA
to Fialka internals merely to avoid ten lines of duplication.

---

## 23. Implementation sequence

Recommended staged replacement:

### Step 2
Add checked `Contact26`, `Contact10`, `Position26`, `Position10`, and a validated
generic permutation type if a shared abstraction is appropriate.

### Step 3
Transcribe and validate all ten large-rotor and five index-rotor wirings.

### Step 4
Implement fixed-position normal large-rotor electrical transforms.

### Step 5
Implement physical reversal and orientation-sensitive coordinate transforms.

### Step 6
Implement true 10-contact index rotors.

### Step 7
Implement control-output banding and index-output pairing as pure functions.

### Step 8
Implement the five-rotor control bank and four simultaneous F/G/H/I signals.

### Step 9
Implement control-rotor metering independently.

### Step 10
Implement cipher-rotor stepping from the index-bank result.

### Step 11
Assemble a frozen cipher bank and verify encode/decode inversion.

### Step 12
Assemble the complete stateful CSP-889 character cycle and freeze step timing.

### Step 13
Implement text-layer Z/SPACE rules.

### Step 14
Add strongly typed configuration and full key validation.

### Step 15
Add independent historical/interoperability known-answer vectors.

### Step 16
Replace the old `Sigaba` public implementation and add `Block` compatibility.

### Step 17
Update `examples/demo.rs`, README and TUI only after the machine passes KATs.

---

## 24. Open verification items

### V1 — exact large-rotor wiring tables

Recover the canonical ten CSP-889 large-rotor permutations from a primary or
high-quality technical source.

### V2 — exact index-rotor wiring tables

Recover and cross-check the five 10-contact index permutations.

### V3 — rotor viewing direction

Freeze the contact-coordinate signs for normal and reversed large rotors.

### V4 — reversed rotor transformation

Verify physical reversal against published mappings rather than deriving it
only from our own normal-orientation code.

### V5 — metered-control rollover

Confirm the exact visible-character rollover for normal and reversed rotors and
how that corresponds to internal `Position26`.

### V6 — character-cycle step timing

Establish whether cipher/control rotor stepping occurs before or after the
electrical transformation of the character.

### V7 — cipher-bank slot traversal

Freeze which physical bank end is keyboard-side in E versus D modes and map it
to array storage.

### V8 — complete known-answer key

Recover at least one full key accompanying a published plaintext/ciphertext
pair or a historical 26-30 check string.

### V9 — index rotor orientation

Confirm whether reversed index-rotor installation was part of operational
CSP-889 keying. Default implementation assumption is normal orientation only
until verified.

---

## 25. Definition of done for Step 1

Step 1 is complete when:

- this document is committed as `doc/sigaba.md`;
- CSP-889 is explicitly separated from CSP-2900;
- 26-contact and 10-contact rotor types are recognized as distinct;
- the control stepping slots 3/4/2 are fixed as fast/medium/slow;
- the F/G/H/I control inputs are explicit;
- control-output banding is explicit;
- index-output pairings are explicit;
- SPACE/Z handling is explicit;
- key validation requirements are explicit;
- all unresolved orientation/timing/wiring questions are tracked rather than
  guessed.

No replacement cipher code should be merged before these conventions are
accepted.

---

# References

## NSA

**History of Converter M-134-C, Volume 1**, declassified NSA Friedman
collection.

https://www.nsa.gov/portals/75/documents/news-features/declassified-documents/friedman-documents/patent-equipment/FOLDER_123/41768449080756.pdf

Used for:

- three-bank architecture;
- ten large / five small rotors;
- interchangeability of large cipher/control rotors;
- stationary index rotors;
- control-slot 3/4/2 fast/medium/slow metering;
- fixed/stationary control slots 1 and 5;
- four-signal stepping-maze description.

## Crypto Museum

**SIGABA — ECM Mark II**.

https://www.cryptomuseum.com/crypto/usa/sigaba/

Used for:

- machine overview;
- encipher/decipher controller behavior;
- `Z -> X` encipher handling;
- SPACE entering the cipher maze as `Z`;
- decrypted `Z` printing as SPACE;
- historical 26-30 check-string procedure.

## USS Pampanito / Maritime Park Association

**ECM Mark II / SIGABA**.

https://www.maritime.org/tech/ecm2.php

Used as an independent mechanical cross-check for control rotor metering.

## Stamp et al.

**SIGABA: Cryptanalysis of the Full Keyspace**.

https://www.cs.sjsu.edu/faculty/stamp/papers/Sigaba2.pdf

Used for the modern exact CSP-889 model:

- four active control inputs F/G/H/I;
- control-output to index-input banding;
- stationary index permutation model;
- paired index outputs driving cipher-rotor steps;
- cryptanalytic/test conventions.

## Additional technical cross-checks

Nils Kopal, **SIGABA CSP-889** challenge/reference material, MysteryTwister.

https://mysterytwister.org/media/challenges/pdf/mtc3-kopal-25-SIGABA-CSP889-01-en.pdf

Joe Dunn, **SIGABA Simulator of the ECM Mark II Cipher Machine**.

https://github.com/JoeDunnStable/sigaba

These should be used as interoperability cross-checks, not as replacements for
the primary sources above.
