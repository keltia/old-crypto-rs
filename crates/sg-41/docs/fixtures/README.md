# SG-41 Step 2 — verified historical fixtures

This is a **data-only** milestone; it does not establish a working encryption engine.

## Primary-source anchors

- [Kopacz & Reuvers, SG-41 technical analysis, v1.05 (2023)](https://www.cryptomuseum.com/pub/files/CM_SG41.pdf), printed page 12, Table 2: four print-head rings.
- Printed page 22, Table 5: six pin-wheel patterns and highlighted initial setting.
- Printed page 23, Table 6: all 32 initial states and plaintext/ciphertext pairs.
- [Hugh Coleman reference](https://github.com/hughcoleman/sg41): independent cross-check of six pin strings and final ciphertext.

## Orientation matters

- `pin_bits_in_table_row_order` records the rows **top-to-bottom** (first listed wheel label to last); it does not make an unproven claim about sensing or rotation direction.
- `print_head` strings record Table 2 physical positions **1 through 26**, read bottom-to-top; the printed table itself runs 26 down to 1.
- `pre_character_trace` is **before** processing each character, not after its last stepping phase.
- The cage uses a distinct +8 sensing position; stepping uses −5. This fixture makes no assumptions about runtime indexing.

## Checked invariants

- Pin bit-string lengths are `25,25,23,23,24,24` (144 total), all binary.
- All ring sequences are permutations of A–Z; rings 1 and 4 match, rings 2 and 3 match.
- Every trace window label belongs to its physical wheel alphabet; all 32 pairs recreate the printed PT and CT.
- The six pin patterns match both printed Table 5 and the cited independent Python reference.

## Important limits

This checks fixture transcription, **not** electrical/mechanical correctness, decryption, or interoperability. Those require an SG-41 implementation, per-phase traces, and known-answer tests in later stages.

## Fixture format

The canonical machine-readable fixture is `sg41-reference.yaml`. Keep zero-padded wheel labels as strings when loading it.
