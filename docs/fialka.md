# Fialka M-125-3 implementation specification

**Project:** `old-crypto-rs`  
**Target:** historically accurate Fialka M-125-3 simulator, with PROTON-2 adjustable rotors  
**Status:** implementation specification — Step 1  
**Date:** 2026-08-11

This document freezes the coordinate systems, terminology, machine boundaries, and
known electromechanical behaviour to be used by the Fialka implementation in
`old-crypto-rs`.

It is deliberately written *before* the rotor code.  Fialka is sufficiently
different from Enigma that a simulator can be internally reversible while still
being historically wrong because of a reversed rotor face, an off-by-one rotor
position, a wrong stepping instant, or an incorrect treatment of the three-point
("Magic") circuit.

The implementation should therefore treat this document as the working contract.
Where historical sources are not yet sufficient to define an exact transformation,
the uncertainty is called out explicitly rather than replaced by an assumption.

---

## 1. Scope

The initial implementation targets:

- the **M-125-3** family;
- the full **30-contact** cipher path;
- ten rotors;
- the punched-card commutator;
- the reflector and three-point / "Magic" circuit;
- distinct coding and decoding modes;
- normal 30-character operation;
- **PROTON-2** adjustable rotors:
  - removable electrical cores;
  - core side 1 / side 2;
  - 30 insertion offsets per side;
  - movable outer/ring setting;
- historically documented rotor sets, beginning with whichever set gives the
  best independently verifiable wiring and stepping vectors.

The following are explicitly *not* part of the first electrical-core milestone:

- printer mechanics;
- paper handling;
- motor simulation;
- electrical timing at transistor/component level;
- physical wear or contact bounce;
- operator procedures that do not affect cryptographic state;
- a graphical reproduction of the machine.

The M-125 predecessor may be supported later.  The implementation should be
architected so that the M-125-3 core does not prevent adding it.

---

## 2. Sources and source precedence

The primary source is the Fialka documentation assembled by Paul Reuvers and
Marc Simons at Crypto Museum, including their reference manual and the machine,
rotor, block-diagram and Magic Circuit documentation.

An independent and especially useful source for rotor mechanics, blocking-pin
positions, and sample stepping behaviour is the rotor documentation by Tom
Perera and David Hamer.

When sources disagree:

1. prefer direct measurements/traces of surviving machines or rotors;
2. prefer the Reuvers/Simons reference manual for complete-machine circuitry;
3. use Perera/Hamer as an independent check, especially for rotor orientation
   and stepping;
4. do not silently choose between conflicting data: add a regression fixture
   and document the decision.

See **References** at the end of this file.

---

## 3. Terminology

Use the following terms consistently in the Rust code and documentation.

### 3.1 Contact

One of the 30 electrical positions used by the Fialka cipher path.

A contact is **not** intrinsically a Unicode character or an ASCII byte.
Cryptographic processing operates on contacts `0..29`.

### 3.2 Rotor / wheel

The complete mechanical cipher wheel mounted on the common spindle.

For PROTON-2 wheels, distinguish the complete wheel from its removable wiring
core and from its adjustable outer/ring relationship.

### 3.3 Rotor core

The removable 30-to-30 electrical permutation ("wiring maze") used by
PROTON-2 rotors.

### 3.4 Rotor body / ring

The mechanical portion carrying the position markings and advance-blocking
pins.  Its relationship to the wiring core can be changed by the ring setting.

### 3.5 Position

The current rotational position of a mounted rotor in the machine.

This is dynamic machine state and changes during stepping.

### 3.6 Core insertion offset

The rotational relationship between the removable wiring core's index mark and
the wheel body.

This is key material, not dynamic stepping state.

### 3.7 Core side

PROTON-2 cores can be fitted with **side 1** or **side 2** outward.  Reversing
the core changes the effective electrical permutation.

### 3.8 Ring setting

The adjustable relationship between the external lettered ring / blocking-pin
geometry and the wiring core.

This is conceptually similar to an Enigma ring setting but must be modelled
according to Fialka geometry, not by importing an Enigma formula.

### 3.9 Blocking pin

A mechanical pin on a rotor that **inhibits** advance propagation to another
rotor.

Fialka documentation often calls these advance-blocking pins.  Code should
prefer `blocking_pin` rather than the ambiguous `notch`.

### 3.10 Card reader / commutator

The 30×30 punched-card permutation unit.

It is a general 30-contact permutation and is **not self-reciprocal** in
general.  It must not be modelled as an Enigma-style pairwise plugboard.

### 3.11 Magic Circuit

The three-point circuit (`Dreipunktschaltung`) associated with four special
reflector contacts.

The implementation should use the historically descriptive name
`ThreePointCircuit` internally; `MagicCircuit` may be used as an alias in
documentation.

---

## 4. Canonical 30-contact alphabet

The physical rotor positions are marked in this order:

```text
А Б В Г Д Е Ж З И К Л М Н О П Р С Т У Ф Х Ц Ч Ш Щ Ы Ь Ю Я Й
```

The Rust implementation shall use zero-based contact numbering:

| Contact | Mark | Contact | Mark | Contact | Mark |
|--------:|:----:|--------:|:----:|--------:|:----:|
| 0 | А | 10 | Л | 20 | Х |
| 1 | Б | 11 | М | 21 | Ц |
| 2 | В | 12 | Н | 22 | Ч |
| 3 | Г | 13 | О | 23 | Ш |
| 4 | Д | 14 | П | 24 | Щ |
| 5 | Е | 15 | Р | 25 | Ы |
| 6 | Ж | 16 | С | 26 | Ь |
| 7 | З | 17 | Т | 27 | Ю |
| 8 | И | 18 | У | 28 | Я |
| 9 | К | 19 | Ф | 29 | Й |

Suggested type:

```rust
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct Contact(u8);
```

`Contact` construction must reject values outside `0..30`; cryptographic code
should not use `% 30` to hide invalid values.

The mapping above is the **electrical coordinate system**.  Country-specific
keyboard and print-head alphabets are presentation/input layers and must not
change this numbering.

---

## 5. Physical orientation and rotor numbering

This section is normative.

When the Fialka is viewed in its normal operating orientation:

```text
LEFT                                                        RIGHT
reflector   rotor 1   rotor 2   ...   rotor 9   rotor 10   entry/keyboard
```

Perera/Hamer describe rotor **A (1)** at the far left and rotor **K (10)** at
the far right.

Therefore:

- physical rotor indices increase **left-to-right**: `1 .. 10`;
- the keyboard/input side is on the **right**;
- the reflector is on the **left**;
- the forward electrical path from keyboard to reflector crosses the rotors
  in physical order:

```text
10 → 9 → 8 → 7 → 6 → 5 → 4 → 3 → 2 → 1
```

- the return electrical path crosses:

```text
1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10
```

This distinction must be visible in code.  Do **not** name an array index
"forward rotor number".

Recommended storage convention:

```text
rotors[0] == physical rotor 1 (leftmost)
...
rotors[9] == physical rotor 10 (rightmost)
```

and iterate with `.iter().rev()` for the keyboard-to-reflector traversal.

### 5.1 Rotor faces

Perera/Hamer describe:

- the **right** rotor face as the input-contact side;
- the **left** rotor face as the output-contact side;
- current travels right-to-left on the first traversal.

The first implementation shall name transformations by physical/electrical
direction rather than by an ambiguous `encrypt()`/`decrypt()`:

```rust
right_to_left(...)
left_to_right(...)
```

A later higher-level API may call them `forward` and `reverse` after tests fix
the convention.

---

## 6. Rotor identity versus rotor slot

Fialka has ten rotor identities, marked by the first ten letters:

```text
А Б В Г Д Е Ж З И К
```

These identities must not be conflated with the ten *physical slots* in the
machine.

Use distinct concepts, e.g.:

```rust
struct RotorId(u8);    // which wiring/body
struct RotorSlot(u8);  // where it is mounted, 0..9
```

A key can therefore specify a permutation of rotor identities over the ten
slots without losing identity.

For PROTON-2, wiring cores may additionally be moved between wheel bodies, so
the implementation must distinguish:

- rotor/wheel body identity;
- wiring-core identity;
- physical slot.

These are three separate values.

---

## 7. Fixed rotor electrical transform

A rotor wiring is a permutation of 30 contacts.

At the rotor's documented **base state**:

- rotor at position `А` / contact 0;
- PROTON-2 ring at `А`;
- PROTON-2 core index at `А`;
- core side 1 outward;

the effective mapping must reproduce the published wiring for the equivalent
fixed rotor.

Represent the static wiring as:

```rust
struct Permutation<const N: usize> {
    forward: [u8; N],
    inverse: [u8; N],
}
```

Construction must validate bijectivity once.

### 7.1 Required electrical invariant

For every rotor state and every contact:

```text
left_to_right(right_to_left(x)) == x
right_to_left(left_to_right(x)) == x
```

This proves local inversion only.  It is **not** a historical-accuracy test.

### 7.2 Coordinate formula policy

Do not freeze a guessed sign convention for rotor displacement until the
published wiring table has been transcribed and at least one non-zero rotor
position has been checked against a reference transformation.

The implementation must nevertheless expose a single helper for rotating
contact coordinates, so that any sign correction is local rather than spread
through the machine.

Example shape:

```rust
fn to_core_frame(machine_contact: Contact, position: Position) -> Contact;
fn from_core_frame(core_contact: Contact, position: Position) -> Contact;
```

A regression test must settle their exact signs before Phase 5 is considered
complete.

---

## 8. PROTON-2 rotor configuration

PROTON-2 introduced removable, reversible wiring cores and adjustable ring
settings.

A core:

- has two sides, labelled 1 and 2;
- can be inserted in 30 angular positions on side 1;
- can be reversed and inserted in 30 angular positions on side 2;
- can be inserted into a different wheel body.

Thus a core has 60 orientations within a body, before considering ring setting.

The documented **base position** is:

```text
core side:       1
core index mark: aligned with А
ring setting:    А
```

In this state a PROTON-2 wheel is electrically/mechanically compatible with the
corresponding non-adjustable rotor.

### 8.1 State separation

The Rust model must not collapse these into one offset:

```rust
struct MountedRotor {
    body_id: RotorBodyId,
    core_id: RotorCoreId,

    core_side: CoreSide,
    core_offset: Contact,

    ring_setting: Contact,
    position: Contact,
}
```

The exact final fields may differ, but these independent concepts must remain
representable.

### 8.2 Important implementation rule

The wiring core transform and the blocking-pin transform must be computed from
their own frames.

Changing the ring setting changes the relationship between electrical wiring
and the mechanical blocking pins.  It must therefore affect stepping without
being incorrectly treated as merely another whole-rotor position.

### 8.3 Reversed core

Do not assume "side 2" is represented only by using `permutation.inverse()`.

A physically reversed core can introduce both reversal of direction and a
coordinate reflection/rotation depending on contact numbering conventions.
Derive the exact side-2 transformation from published reversed-core data and
lock it with tests.

---

## 9. Rotor movement directions

Adjacent Fialka rotors turn in opposite directions.

Using physical slot numbers 1..10, and viewing the wheel markings from above:

- **odd-numbered slots** move their upper letters **towards the keyboard**;
- **even-numbered slots** move their upper letters **away from the keyboard**.

The implementation should encode motion direction by slot, not by rotor
identity:

```rust
fn stepping_direction(slot: RotorSlot) -> Direction;
```

A rotor moved to another slot therefore follows the slot's mechanical
direction.

The exact mapping of `TowardsKeyboard` / `AwayFromKeyboard` to `+1` / `-1` in
our zero-based `Contact` coordinate system must be settled by the known
20-keypress stepping trace before it becomes a public assumption.

---

## 10. Stepping topology

Two wheels are unconditional drivers:

- wheel/slot **2** advances on every keypress;
- wheel/slot **9** advances on every keypress.

The even chain propagates from left to right:

```text
2 → 4 → 6 → 8 → 10
```

The odd chain propagates from right to left:

```text
9 → 7 → 5 → 3 → 1
```

A blocking pin **inhibits** propagation.

Thus:

- slot 2 controls whether slot 4 may advance;
- slots 2 and 4 can inhibit slot 6;
- slots 2, 4 and 6 can inhibit slot 8;
- slots 2, 4, 6 and 8 can inhibit slot 10;

and symmetrically:

- slot 9 controls whether slot 7 may advance;
- slots 9 and 7 can inhibit slot 5;
- slots 9, 7 and 5 can inhibit slot 3;
- slots 9, 7, 5 and 3 can inhibit slot 1.

This cumulative interpretation follows the Perera/Hamer description that a
blocking pin in any upstream rotor's drive slot prevents the downstream rotor
from advancing.

### 10.1 Mechanical engagement reference positions

Perera/Hamer report the drive-cog reference positions, with the wheels set to
`А`, as:

- even chain: physical position **18** in their one-based numbering;
- odd chain: physical position **21** in their one-based numbering.

These correspond to source-table positions and must **not** be blindly
converted to zero-based indices without checking the source's alignment
convention.

The implementation shall initially store these as named physical constants,
with conversion to the internal coordinate system isolated in one place.

### 10.2 Step evaluation instant

The stepping decision for a keypress should be represented as two phases:

```text
1. inspect the pre-step mechanical state and determine the set of slots that move;
2. apply the selected movements together.
```

This matches the physical idea of the transport combs and prevents a software
artefact where moving slot 2 first changes the blocking condition used for
slot 4 in the *same* keypress.

**Verification requirement:** this convention is not considered final until
the implementation reproduces the published sample stepping sequence from an
all-`А` start.

### 10.3 Cipher timing relative to stepping

Historical sources confirm that a keypress causes wheel movement, but this
specification does **not yet freeze** whether the electrical transform for a
character is sampled before or after the rotor movement.

This is a blocking verification item.

The choice must be established from an operational manual, circuit timing, or a
known-answer ciphertext and then locked by a test.  Do not infer it from Enigma.

---

## 11. Punched-card commutator

The M-125-3 card reader exposes a 30×30 contact matrix programmed by a punched
card containing one selected connection in each row/column.

Model it as a general permutation:

```rust
struct Commutator(Permutation<30>);
```

It is not required to be self-inverse.

The signal passes through the commutator twice:

```text
keyboard → commutator → entry disc → rotor drum → reflector
reflector → rotor drum → entry disc → commutator → output
```

Therefore, if the card maps the keyboard-side contact system to the drum-side
contact system with permutation `P`, the return direction must use `P⁻¹`.

This directionality must be verified against the card-reader documentation and
test triangle ("unity matrix").

The implementation must reject:

- duplicate row assignments;
- duplicate column assignments;
- missing assignments;
- values outside `0..29`.

---

## 12. Static entry disc

There is a static entry disc between the card reader and rotor stack.

Do not assume it is electrically an identity solely because it does not move.
Its actual contact mapping/orientation must be established from the reference
manual/circuit data.

Until verified, represent it as an explicit component:

```rust
struct EntryDisc {
    wiring: Permutation<30>,
}
```

If documentation proves that the implementation-coordinate mapping is identity,
retain the conceptual component but it may compile down to an identity
permutation.

---

## 13. Reflector and three-point ("Magic") circuit

Fialka must **not** be implemented as a simple 30-contact involutive reflector.

For the normal 30-contact M-125/M-125-3 path, the documented special contacts
are:

- reflector pair **13–16** is broken;
- reflector contact **13** becomes the plaintext-enable signal;
- reflector contact **16** enters the three-point circuit;
- reflector pair **18–24** is broken;
- reflector contacts **18** and **24** also enter the three-point circuit.

The remaining ordinary reflector contacts are connected in reciprocal pairs.

> The contact numbers in this section are the historical/source numbering and
> must be converted deliberately into the implementation's zero-based contact
> coordinates after the reflector numbering origin is confirmed.

### 13.1 Plaintext-enable contact

If the reflector path reaches the plaintext-enable line, no normal return
signal travels back through the drum.  Instead, the original key's mechanically
generated 5-bit value overrides the encoded output.

At the abstract cipher-machine level the semantic result is:

```text
output symbol == original input symbol
```

The simulator does not need to reproduce the transistor or diode-matrix
electrical implementation to model this effect.

### 13.2 Three-point cycle

The three special signal lines form a directed 3-cycle.

Crypto Museum describes one direction as:

```text
18 → 24
24 → 16
16 → 18
```

The machine becomes non-reciprocal because of this directed cycle.

### 13.3 Coding versus decoding

The MODE selector reverses the effective direction of the three-point cycle by
swapping two of its lines.

Crypto Museum's circuit description states that reflector lines 16 and 24 are
cross-connected between coding and decoding configurations.

Therefore the implementation requires distinct machine operations:

```rust
enum CipherDirection {
    Encode,
    Decode,
}
```

and must not implement decoding merely by resetting the machine and invoking
the identical encode path.

The ordinary paired reflector contacts remain reciprocal; only the special
path introduces the direction-dependent behaviour.

### 13.4 Abstraction

Suggested model:

```rust
struct ReflectorUnit {
    ordinary_pairs: ...,
    three_point: ThreePointCircuit,
    plaintext_enable: ...,
}

impl ReflectorUnit {
    fn transform(
        &self,
        contact: Contact,
        direction: CipherDirection,
        original_input: Contact,
    ) -> ReflectorResult;
}
```

`ReflectorResult` may need to distinguish:

```rust
enum ReflectorResult {
    ReturnThroughDrum(Contact),
    Plaintext(Contact),
}
```

This is preferable to forcing the plaintext-enable path into a fake
permutation.

---

## 14. Full 30-contact electrical path

For normal (`30`) operation, abstract the machine as:

```text
INPUT CONTACT
    │
    ▼
PUNCHED-CARD COMMUTATOR
    │
    ▼
STATIC ENTRY DISC
    │
    ▼
ROTOR 10  right→left
    │
ROTOR 9
    │
...
    │
ROTOR 1
    │
    ▼
REFLECTOR / THREE-POINT CIRCUIT
    │
    ├──── plaintext-enable ───────────────► OUTPUT ORIGINAL SYMBOL
    │
    ▼
ROTOR 1   left→right
    │
ROTOR 2
    │
...
    │
ROTOR 10
    │
    ▼
STATIC ENTRY DISC (reverse direction)
    │
    ▼
PUNCHED-CARD COMMUTATOR (reverse direction)
    │
    ▼
OUTPUT CONTACT
```

The exact entry-disc orientation remains a verification item.

The cryptographic core should return contacts, not bytes or Unicode characters.

---

## 15. 30 ↔ 10 reduction switch

The M-125-3 adds a `30 ↔ 10` selector for numbers-only traffic.

In `10` mode:

- only ten keyboard positions are operable;
- twenty reflector lines are rerouted toward the card-reader/input path;
- signals can loop until they produce one of the ten permitted numerical
  outputs;
- the reflector/Magic Circuit interaction is therefore more complex than in
  normal 30-contact operation.

This feature is part of the historically correct M-125-3 but should be
implemented **after** normal 30-contact operation has known-answer tests.

Architecturally reserve:

```rust
enum ContactMode {
    Full30,
    Numeric10,
}
```

Do not approximate `Numeric10` by simply rejecting twenty input symbols.

---

## 16. Keyboard, print alphabets, and text modes

The machine's cryptographic core is a 30-contact machine.  Keyboard and printed
characters vary with national variant and text mode.

Keep three layers separate:

```text
Unicode / operator text
        ↓
keyboard/text-mode mapping
        ↓
Contact(0..29)
        ↓
cryptographic machine
        ↓
Contact(0..29)
        ↓
print-head/text-mode mapping
        ↓
Unicode / operator text
```

M-125-3 variants include:

- Cyrillic and country-specific Latin mappings;
- letters-only compatibility mode;
- mixed letters/numbers operation;
- numbers-only (`30 ↔ 10`) mode.

No ASCII-centric assumptions belong in `Rotor`, `RotorDrum`, `Commutator`, or
`ReflectorUnit`.

---

## 17. 5-level paper-tape encoding

Fialka uses a proprietary five-level tape code rather than ITA-2/MTK-2.

There are 32 possible five-bit patterns:

- 30 represent the machine's normal character positions;
- one is SPACE;
- `00000` is NULL/STOP.

This is an I/O encoding layer, not the internal cipher representation.

Suggested future abstraction:

```rust
struct FialkaTapeCode(u8);
```

with explicit conversion to/from keyboard/contact events.

Do not represent a contact merely as `tape_byte & 0x1f`.

---

## 18. State model

At minimum, dynamic cryptographic state contains:

```text
10 current rotor positions
```

Static/keyed configuration contains at least:

```text
rotor bodies / identities
rotor-core identities
rotor slot ordering
core side for each rotor
core insertion offset for each rotor
ring setting for each rotor
punched-card commutator
machine variant / rotor series
cipher direction (operator mode)
30/10 operating mode
text/keyboard mode where relevant
```

The precise split between immutable configuration and mutable state should
allow:

```rust
let machine = Fialka::new(config)?;
let initial = machine.snapshot();

machine.process(...);

machine.restore(initial);
```

without reconstructing or reparsing rotor data.

---

## 19. Proposed Rust coordinate types

These are guidance, not yet a frozen public API:

```rust
struct Contact(u8);          // 0..29
struct Position(Contact);

struct RotorSlot(u8);        // 0..9, physical slots 1..10
struct RotorBodyId(u8);
struct RotorCoreId(u8);

enum CoreSide {
    One,
    Two,
}

enum RotationDirection {
    TowardsKeyboard,
    AwayFromKeyboard,
}

enum CipherDirection {
    Encode,
    Decode,
}
```

Prefer semantic methods over naked modular arithmetic.

Examples:

```rust
position.step(direction);
rotor.right_to_left(contact);
rotor.left_to_right(contact);
drum.determine_steps();
drum.apply_steps(...);
```

---

## 20. Required test hierarchy

A correct simulator needs more than round-trip tests.

### 20.1 Permutation tests

For every published wiring/card:

- all values in `0..29`;
- every value appears once;
- inverse is exact.

### 20.2 Rotor base-wiring tests

For each rotor identity, assert specific published contact mappings in the
documented base state.

### 20.3 Rotor-position tests

For non-zero positions, verify known external contact-to-contact mappings so
that rotational sign conventions are tested.

### 20.4 Reversed-core tests

Use published side-2 wiring data to verify the exact physical reversal
transformation.  Do not derive it only from our own side-1 algorithm.

### 20.5 Ring-setting tests

Prove that changing ring setting changes blocking-pin/core alignment correctly
without accidentally changing unrelated state.

### 20.6 Stepping trace

The Perera/Hamer sample starts with all ten rotor positions at `А` and records
the positions after each of the first 20 keypresses.

This trace is a mandatory fixture.

The implementation must reproduce it exactly before stepping is considered
correct.

### 20.7 Three-point circuit tests

Test the special reflector paths directly for both modes:

```text
Encode:  directed three-cycle
Decode:  inverse directed three-cycle
Plaintext-enable: returns original input symbol
```

### 20.8 Frozen full-machine tests

With rotor stepping disabled/frozen, exhaustively map all 30 inputs for one or
more complete configurations.

This isolates electrical correctness from mechanical correctness.

### 20.9 Historical known-answer tests

At least one independently sourced tuple is required:

```text
complete machine configuration
starting rotor state
mode
plaintext
ciphertext
```

Round-tripping our own output is not sufficient evidence of historical
correctness.

---

## 21. Implementation rules derived from this specification

1. **No `unsafe` is expected.**
2. **No ASCII in the electrical core.**
3. **No global mutable machine state.**
4. **No `% 30` as input validation.**
5. **No assumption that the commutator is reciprocal.**
6. **No assumption that encode and decode are the same operation.**
7. **No assumption that PROTON-2 side 2 is merely `Permutation::inverse()`.**
8. **No assumption that an Enigma ring-setting formula applies unchanged.**
9. **No stepping logic embedded invisibly inside a rotor lookup.**
10. **No acceptance criterion based only on `decrypt(encrypt(x)) == x`.**
11. Physical slot numbering and electrical traversal order must remain
    explicitly distinguishable.
12. Unverified historical details must remain named TODOs, not become silent
    constants.

---

## 22. Open verification items before coding reaches the corresponding phase

These are intentionally unresolved in this Step-1 document.

### V1 — exact rotor displacement signs

Determine the exact mapping between:

- visible rotor mark;
- right-face contact number;
- left-face contact number;
- our zero-based `Contact`.

Resolve using a non-zero-position reference mapping.

### V2 — exact side-2 PROTON-2 transform

Derive and verify the coordinate reflection/rotation required when the wiring
core is physically reversed.

### V3 — exact ring-setting transform

Establish the precise relationship among:

- outer/ring mark;
- blocking-pin physical location;
- core index;
- visible rotor position.

### V4 — drive-cog source positions

Convert the historical one-based "18" (even) and "21" (odd) drive engagement
positions into the canonical internal coordinate frame only after checking the
source's viewing side and indexing origin.

### V5 — step-before-versus-after electrical sampling

Establish whether the rotors reach their new state before the contact is
electrically encoded for that keypress.

### V6 — entry-disc mapping

Determine whether the static entry disc is identity in our chosen coordinate
frame or has an explicit permutation/orientation transformation.

### V7 — reflector numbering origin

Confirm the exact conversion of historical reflector contacts 13, 16, 18 and
24 to zero-based `Contact` values and verify the ordinary paired wiring.

### V8 — known-answer full-machine vector

Locate or derive from an independently validated simulator/manual a complete
known-answer test for normal 30-contact operation.

### V9 — 30↔10 reduction algorithm

Transcribe the exact M-125-3 rerouting behaviour before implementing
numbers-only mode.

### V10 — national keyboard/print mappings

Treat Russian, Polish, Czech and other variants as separate data sets and
verify each against primary/curated documentation before adding it.

---

## 23. Definition of done for Step 1

Step 1 is complete when:

- this specification is checked into `doc/fialka.md`;
- implementation contributors agree on the physical numbering convention;
- code will use a 30-contact internal coordinate system independent of text;
- rotor identity, rotor body, rotor core and physical slot are understood as
  separate concepts;
- PROTON-2 core orientation, insertion offset, ring setting and runtime
  position are not conflated;
- the stepping topology is fixed;
- encode/decode asymmetry caused by the three-point circuit is explicit;
- every unresolved sign/orientation/timing issue is listed above rather than
  guessed.

The next implementation step should be `Contact` plus a validated
`Permutation<30>` abstraction, followed by transcription of one rotor set and
reference fixtures.

---

# References

## Primary reference set

Paul Reuvers and Marc Simons, **Fialka — M-125 cipher machine**, Crypto Museum.

- https://www.cryptomuseum.com/crypto/fialka/
- https://www.cryptomuseum.com/crypto/fialka/man.htm
- Reference Manual: https://www.cryptomuseum.com/pub/files/Fialka_200.pdf

The Crypto Museum reference set includes machine descriptions, block diagrams,
circuit diagrams, rotor information and simulator-oriented data.

## M-125-3 machine description

Crypto Museum, **M-125-3 Fialka**.

- https://www.cryptomuseum.com/crypto/fialka/m125_3/

Used for:

- canonical 30-position rotor alphabet;
- ten-wheel construction;
- wheel directions and stepping topology;
- PROTON-2 core/ring description;
- card-reader behaviour;
- 30↔10 mode;
- text/keyboard modes.

## Rotor wiring and stepping

Tom Perera and David Hamer, **Technical Description and Wiring Data for Rotors
for the M-125-MN and M-125-3MN/-3MP3 Russian Fialka Cipher Machines** (2005).

- https://enigmamuseum.com/mfr.htm

Used as an independent source for:

- physical left/right rotor faces;
- physical rotor numbering;
- alternating rotation directions;
- blocking-pin mechanics;
- drive-cog reference positions;
- PROTON-2 base configuration;
- published sample stepping data.

## Magic / three-point circuit

Crypto Museum, **Magic Circuit — Fialka**.

- https://www.cryptomuseum.com/crypto/fialka/magic.htm

Used for:

- special reflector contacts;
- plaintext-enable behaviour;
- directed three-point cycle;
- encode/decode mode reversal.

## Block diagram

Crypto Museum, **Fialka block diagram**.

- https://www.cryptomuseum.com/crypto/fialka/block.htm

Used for:

- high-level signal path;
- keyboard 5-bit path;
- reflector/Magic Circuit relationship;
- M-125-3 30↔10 reduction path.

---

## Notes on citations and reproducibility

The URLs above should remain in the repository document even if data tables are
later transcribed into Rust constants.  Each such constant should cite its
source immediately in a code comment or in an adjacent data README.

For rotor wiring, blocking-pin tables and known-answer vectors, prefer storing
the original source transcription in test fixtures and generating the Rust
constant form where practical.  This reduces the risk that a typo in a source
table becomes an undocumented implementation constant.
