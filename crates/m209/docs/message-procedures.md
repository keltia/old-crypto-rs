# M-209 message indicators and key-list procedures (Step 18)

Status: **specification and evidence inventory only**. No production implementation is introduced in Step 18. Implementation stages 19–23 require separate approval.

## Scope and historical accuracy

Do **not** confuse these documented variants:

1. **1944 War Department TM 11-380, §9(c)** is explicitly a *training example*. Its six-letter message indicator is **directly** the starting alignment of the six key wheels; it does **not** describe the derived internal indicator method below. The manual says methods vary with the operational system. Its example of two five-letter indicator groups is `FWQAH NKELP` (system `FW`, wheel alignment `QAHNKE`, key-list indicator `LP`). Indicator groups are repeated after the ciphertext. Source: TM 11-380, printed pp. 19–21, §9.
2. **U.S. Army training-film / simulated “standard” procedure** derives a concealed internal starting alignment from the external wheel setting by enciphering repeated copies of a one-letter system indicator. In transmission, its system letter is duplicated to occupy two characters. This procedure is described in the Virtual Hagelin M-209 tutorial, Brian Neal's `StdProcedure`, and contemporaneous training-film discussions. These are corroborating accounts of a *particular* procedure, not proof that all wartime traffic followed it.

Implement the modes distinctly. The first planned fully interoperable mode is the **derived-indicator training procedure**, with an explicitly selected procedural profile. A direct-indicator profile is a possible subsequent feature, not a silent fallback.

## Authoritative and reference sources

| ID | Source | What it establishes | Limitations |
|---|---|---|---|
| P1 | [War Department TM 11-380 (17 March 1944)](https://m209.virtualcolossus.co.uk/M209%20Manual.pdf), §9–§10, printed pp. 19–21 | Three indicator types; directly transmitted six-letter alignment in a *training example*; opening/closing groups; handwritten X padding; operating guidance | Does not prescribe a single universal indicator procedure; §9(c) explicitly labels its construction a training example |
| P2 | [Virtual Hagelin M-209 tutorial](https://m209.virtualcolossus.co.uk/tutorial.html), “Example of enciphering a message” | Twelve repeated system letters, derived internal wheel setting by skipping unavailable letters, documented full message example, unenciphered X padding | Modern historical simulator/tutorial rather than an original operator's key list |
| P3 | [Brian Neal, `StdProcedure` documentation](https://m209.readthedocs.io/en/latest/procedure.html) | Software envelope, key-list indicator, decryption preparation and API semantics | Randomly generated examples alone are not reproducible without key material |
| P4 | [Brian Neal, `m209/procedure.py` implementation](https://github.com/gremmie/m209/blob/master/m209/procedure.py) | Exact algorithm used by that simulator; reveals 24-letter encryption fallback and 12-letter decryption derivation | The asymmetric lengths are a compatibility concern, not an historical rule |
| P5 | [Brian Neal, key-list documentation](https://m209.readthedocs.io/en/latest/keylist.html) | Two-character key-list identifiers, lug and pin settings, 26-letter check, external file conventions | Generation algorithm is heuristic, not an exhaustive encoding of historic key-generation rules |
| P6 | [U.S. wartime M-209 training film transcript](https://www.ilord.com/m-209-video-and-transcript) | Repeated letter / internal alignment and treatment of trailing X letters on receipt | Secondary transcript; compare particular operating steps against film/manual |

## Existing crate primitives to reuse

- `M209Config` for already validated pin, lug and initial-wheel data; `M209Machine` for continuous contact conversion; `Contact` and typed wheel positions for strict indicator checking.
- `text` functions for machine-text normalization (`Z` denotes a space), but **do not** infer that decoded `Z` was originally a space; raw output must remain accessible.
- `old_crypto_rs::helpers::output_as_block` for five-letter formatting. Do not reimplement grouping or introduce another `Block` trait.
- `noyalib` and Serde for configuration I/O, `thiserror` for structured errors, and the existing `m209ctl` Clap conventions.

## Derived-indicator training procedure: normative proposed profile

Parameters are explicit so tests do not rely on randomness: validated daily `KeyList`, two-uppercase-letter key-list identifier, one uppercase system letter `S`, and a legal six-letter *external* wheel alignment `E`. A production call without `E` or `S` can later obtain them from a suitable random source; random generation is not required in Steps 19–21.

### Encrypt

1. Select and validate the requested key-list entry; install its wheel-pin and drum settings.
2. Set all wheel windows to `E`, reset the character count and initialize independent machine state.
3. Encipher the system letter `S` **twelve** successive times, preserving the ungrouped twelve-letter result `R`. The wheels advance for every contact.
4. Traverse `R` left-to-right, seeking the first letter admitted by wheel 1's historical alphabet; then the next admitted by wheel 2, and so on through wheel 6. Discard unadmitted letters. This yields the six-letter internal indicator `I`. If fewer than six usable letters occur in the twelve, return a specific **insufficient indicator letters** error and require a newly selected external indicator; do not panic or quietly extend the stream in this profile.
5. Reset machine state and set windows to `I`; encipher the normalized message body (`space` → `Z`). Group the resulting ciphertext in blocks of five.
6. Append literal `X` letters to fill the final group **after** encryption, not as M-209 input. Record how many were added (0–4) when the message is generated; a received message typically cannot distinguish this padding from genuine ciphertext.
7. Compose two groups: `G1 = SS + E[0..3]`, `G2 = E[3..6] + key_id`, using ASCII letter positions. Transmit `G1 G2 BODY G1 G2`.

### Decrypt

1. Accept grouped or ungrouped uppercase ciphertext. Check that at least two five-letter opening and two five-letter closing groups exist plus a nonempty message body; require the last two groups to match the first two exactly, and the first two characters of `G1` to agree.
2. Parse `S = G1[0]`, `E = G1[2..5] + G2[0..3]`, `key_id = G2[3..5]` and validate `E` using *each wheel's* alphabet (not only A–Z).
3. Look up `key_id` without guessing or substituting another key; an absent key is an error. Reproduce the twelve-letter `R` and derived internal alignment `I` identically to encryption.
4. Set windows to `I`, reset message count, decrypt the grouped body. Expose **raw decoded contacts** separately from historically formatted text (`Z` → space).
5. Treat trailing X padding as **ambiguous**. Operators were instructed to process all received body characters because an `X` might be actual ciphertext. Do not blindly remove the last 0–4 decrypted letters; provide raw complete output and make any application-specific padding policy explicit.

### Alternate procedures and known divergence

- The **TM 11-380 direct-indicator training example** uses the six wheel letters themselves as the initial message alignment, with no twelve-letter derivation. Its system indicator can be two *different* letters (`FW`). Therefore it must not be parsed using the derived-profile requirement that the first two letters are identical.
- `gremmie/m209`'s source currently uses **24** repeats when *encrypting* to increase the chance of finding six accepted wheel letters, but **12** when *decrypting*. Such a message may fail to decode if the six selected letters require input beyond the twelfth. This is a reference-code behavior to test and document, not a safe default. Preserve 12 for the historical profile; if a 24-letter compatibility option is later offered, encode its protocol and decryption rule explicitly.
- Requirements on randomness, non-reuse of external indicators, and operational key generation belong in the later key-list and message API. No deterministic PRNG or insecure default should be added for convenience.

## Evidence fixtures and verification status

### F1: complete derived-indicator worked example (P2)

- Daily key: the **TM 11-380 sample pins and lug bars** already carried in `MANUAL_1944_PINS` / `manual_1944_drum()`. This combination is shown in the simulator tutorial's setup sheet.
- System `K`; transmitted prefix `KK`; external wheel windows `DUFLJB`; two-letter key-list label `XA` (illustrative label identifying those settings).
- Twelve enciphered system letters: `PEQGBJGCDFUP` (formatted `PEQGB JGCDF UP`).
- Selected internal wheel alignment: `PEQGBJ`.
- Body plaintext: `OPERATION ZEBRA STARTS AT SUNSET`.
- Body ciphertext before handwritten padding: `KBMUNODDDCYWLVMRBVUSQYRHTXNZUIHX` (grouped `KBMUN ODDDC YWLVM RBVUS QYRHT XNZUI HX`).
- Body after **three** handwritten Xs: `KBMUN ODDDC YWLVM RBVUS QYRHT XNZUI HXXXX`.
- Full transmitted message:

  ```text
  KKDUF LJBXA KBMUN ODDDC YWLVM RBVUS QYRHT XNZUI HXXXX KKDUF LJBXA
  ```

- Status: **published source reference, not yet executed as a Rust test**. Step 20 must confirm `R` and `I` from the 1944 fixture; Step 21 must confirm the exact body and full envelope. Historical text display loses literal Z in `ZEBRA`.

### F2: envelope-only parser fixture (P3)

```text
YYGBM ENNHT VBMTJ PEEFV JWLUU PAFTS VOHEA QEPEQ OKVUA XDAUX YYGBM ENNHT
```

Expected parsed fields: system `Y`; external `GBMENN`; key ID `HT`; body `VBMTJ PEEFV JWLUU PAFTS VOHEA QEPEQ OKVUA XDAUX`.

Status: **sufficient to test parsing/framing**, not to reproduce encryption without the particular randomly generated key list from the example.

### F3: reference library tutorial (P3 and [tutorial](https://m209.readthedocs.io/en/latest/tutorial.html))

```text
IIPDU FHLMB LASGD KTLDO OSRMZ PWGEB HYMCB IKSPT IUEPF FUHEO NQTWI VTDPC GSPQX IIPDU FHLMB
```

Expected parsed fields: system `I`; external `PDUFHL`; key ID `MB`.

Status: **envelope parser fixture only** unless the specific `MB` key list from that tutorial is supplied; don't label it as an independently executable ciphertext vector.

### F4: 1944 manual direct-indicator framing (P1)

```text
FWQAH NKELP
```

Parsed under **direct mode**: system `FW`; visible wheel alignment `QAHNKE`; key ID `LP`. Status: authentic manual illustration of header structure, not an encrypted-message test vector.

## Planned test matrix for Steps 19–23

| Level | Required checks |
|---|---|
| Keys (19) | Validate two-letter IDs; duplicate rejection; 27 bar pairs; correct six wheel alphabets; historic 26-A key check; strict YAML; no accidental mutation of shared settings |
| Indicator (20) | Exact `PEQGBJGCDFUP` sequence, `PEQGBJ` selection, rejected wheel letters, exhausted 12-letter stream, repeatability and wheel-index correctness |
| Envelope (21) | Exact F1 complete message; extract F2/F3 fields; reject mismatched trailing groups, wrong system repeats, invalid wheel alignment, short messages, missing keys, nonalphabetic ciphertext |
| Message body (21) | Raw vs `Z`-formatted plaintext; grouping with core helper; explicit post-encryption X padding; preserve decrypted ambiguity at message end; split and reset equivalence |
| CLI (22) | Deterministic explicit system/external indicators; `noyalib` key-store loading; decrypt key selection by ID; stdin/positional input; error exits; no implicit RNG |
| Final (23) | Historical citations, differences between variants, independent cross-implementation checks, complete workspace tests and Clippy, no duplicated core utilities |

## Architecture and staged pause

- **Step 18 (this change):** specification, citations, fixtures, unresolved differences. No Rust changes.
- **Step 19:** typed key-list and key-store model; checked YAML/CLI loader based on `M209Config`. Pause.
- **Step 20:** explicit, deterministic derived-indicator algorithm and independent exact vector. Pause.
- **Step 21:** typed envelope and end-to-end message processing; verified F1 plus parser cases. Pause.
- **Step 22:** CLI `message-encrypt` / `message-decrypt` (or equivalent) with key-list selection. Pause.
- **Step 23:** documentation, full regression matrix, optional demo/TUI examples where warranted, final review. Pause.

**Open questions before Step 19**: whether we should support the 1944 *direct* system-indicator variant in the initial API or defer it, and whether the 24-character reference fallback merits an explicit compatibility profile. Neither is silently enabled in this specification.


## Step 19: Typed key lists and key stores

Implemented in `src/key_list.rs`. `KeyId` is exactly two uppercase ASCII
letters; `KeyList` owns a validated `M209Config` and its verified 26-character
check; `KeyStore` rejects duplicates and requires explicit lookup by key ID.

The example `config/key-list-reference.yaml` contains a **demonstration** key
identified as `XA` using the original TM 11-380 (1944) pin and lug settings.
The `XA` assignment here is for reproducible tests, not evidence of a
historical operational key-list identifier. The `check` field is compared
against actual encryption of 26 A letters at wheel windows `AAAAAA`.

YAML parsing uses `noyalib` and Serde's `deny_unknown_fields`. This step does
not generate random daily keys, infer missing key IDs, derive message
indicators, or produce message envelopes. Those are later steps.
