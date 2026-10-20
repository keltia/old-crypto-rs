# SG-41 historical message procedures

Status: implemented and locally tested through Step 22 (2026-10-20).
The historical indicator has an independent published known-answer check;
a complete archival end-to-end transmission vector remains unavailable.

This document describes the **SG-41** (not SG-41Z) historical keying,
message-indicator, and traffic procedures. It is separate from the mechanical
cipher implementation. Do not silently equate a historical operational key with
a `Sg41Config`, or apply modern normalization to the archival examples.

## Evidence and scope

**Primary documentation identified (not reproduced here):**

- *Vorschrift Nr. 90 Schlüsselgerät 41*, 28 August 1944, especially section C,
  paragraph 5, page 3, held by the Military Historical Institute Prague (VHU),
  sub-collection XVI.
- *Schlüsselgerät 41 und 41Z Gebrauchsanleitung*, 2 September 1944, and a
  six-page field abridgement dated 1 July 1944, at VHU.
- *Monatstafel zum Schlüssel für Gerät 41 Nr. 7 b*, including 16–31 March 1945
  tables and associated daily/disguise keys, at VHU.
- SG-41 documentation in Security Services Archive (ABS), box BF396,
  including file 396/4 (signature 27-19/21-34; differing inventory signature
  27-19/80-03), as catalogued by Antal et al.

**Published, inspectable secondary exposition based directly on the archival
records:** Eugen Antal, Carola Dahlke and Robert Jahn, “Revealing secrets from
WWII: the original German instructions of Schlüsselgerät 41,” *Cryptologia*
50 (2026), no. 3, 235–264; published online 1 December 2025,
https://doi.org/10.1080/01611194.2025.2557311 . Sections 3.4.1–3.4.4 and
Appendices A–B are the central source for this specification.

**Independent explanatory corroboration:**
https://kryptografie.de/kryptografie/chiffre/schluesselgeraet-41.htm .
This is *not* an independent archival transcription and should not overrule
Vorschrift Nr. 90 or the archival study.

Evidence categories used below:
- **Documented:** reported explicitly from archival records by Antal et al.
- **Derived:** algorithm restatement needed for implementation, check against
  archive plates and the whole worked example before claiming historical fidelity.
- **Open:** cannot be fully verified from currently transcribed materials.

## Key material and scope

1. **Monthly table (`Monatstafel`) — documented.** A table with 26 rows labeled
   A–Z; each row is 25 pin-state entries (active `+`, inactive symbol). The
   six wheels together have 144 pins. As specified in Antal et al., footnote
   17, use all 25 symbols for wheels 1–2, the first 23 for wheels 3–4,
   and the first 24 for wheels 5–6.
2. **Daily key (`Tagesschlüssel`) — documented.** Six letters select six rows
   of the monthly table, one for each wheel in order. Reconfigure pin settings
   daily. The example for 16 March 1945 uses `ACHUKW`.
3. **Disguise key (`Tarnschlüssel`) — documented.** For the day, a permutation
   of A–Z with a position-aligned length-26 sequence of digits from 1–9
   (without zero). Duplicates are necessarily allowed in the digits. This is
   *not* a 26-digit permutation. Figure 12 supplies the 16 March 1945 key:
   alphabet `SYIZBJEHOCKUGPDRVFTXLNMWAQ` and digits
   `96585138157834794289563262`. These are recorded in the historical
   YAML fixture and checked by `tests/message_indicator_historical.rs`.
4. **Station number — documented.** Each station has two two-digit numbers.
   They change at the start of each calendar quarter (1 Jan, 1 Apr, 1 Jul,
   1 Oct). Wheels 5 and 6 are positioned according to the **sending**
   station's two numbers, for both encryption and decryption. Wheel 5 bears
   values 01–24; wheel 6 bears a nonsequential set of 24 numbers in the range
   00–57. The example sending station uses `18 37`. Do not equate these
   displayed station numbers with zero-based wheel offsets without consulting
   the historical wheel marking maps.
5. **Per-message indicator (`Spruchschlüssel`) — documented.** Select four
   random letters, different for each message; set wheels 1–4 to their
   positions. The letters are transmitted only in a disguised eight-letter
   encoding plus two padding characters. Example: `KNVP`.

The device's rapid reset-to-zero mechanism was an emergency erasure measure,
not a prescribed way to install daily pins (Antal et al., section 3.4.3).

## Sending procedure

Documented sequence, with implementation boundaries noted:

1. Select correct monthly table and six-letter daily key. Configure all six
   wheel pin patterns from the corresponding monthly-table rows.
2. Select a fresh four-letter message indicator and set wheels 1–4 to it.
3. Set wheels 5–6 to the *sender's* station number.
4. Prepare plaintext according to the historical SG-41 input rules below;
   encipher the message with the normal core algorithm, recording the actual
   first **three ciphertext letters** `C0 C1 C2`.
5. Pad the ciphertext, if necessary, by **enciphering additional randomly
   selected letters**, until its length is divisible by five. This padding
   changes the machine state and is *ciphertext*, not literal cleartext
   appended to the ciphertext output. The historical maximum is 600 letters
   of ciphertext per message; longer messages must be split into independently
   keyed parts, preferably of different lengths.
6. Disguise the four-letter indicator using the daily disguise key and the
   first three (pre-padding) ciphertext letters (algorithm below).
7. Append two random letters to the eight-letter disguised indicator;
   prepend the resulting ten-letter header to the ciphertext, and format in
   five-letter groups. The first real ciphertext character is transmitted as
   position **11** (1-based), following the ten-letter header.

**Historical framing qualification:** The implementation limits the
*machine-produced ciphertext body*, including encrypted padding, to 600 letters.
The archival report gives a 600-letter maximum; whether the original manual
counts the header or describes further boundary exceptions has not been
independently verified here. The enforced limit is an implementation decision.

## Masking the message indicator

The following is a compact mathematical restatement of Appendix B of Antal et
al.; character positions are zero-based below. Alphabetic `+1` in step 1 is
in ordinary A–Z order, **not** disguise-key order. Every other letter lookup
and shift in steps 2–4 is performed in the daily scrambled alphabet.

Definitions:

- `I[0..4]`: four ordinary A–Z indicator letters.
- `A[0..26]`: daily scrambled-alphabet permutation; `D[0..26]`: aligned
  digits `1..9` (both arrays of length 26).
- `C[0..3]`: first three genuine ciphertext letters.
- `pos_A(x)`: unique index of letter `x` in `A`.
- `succ(x)`: one-character forward wrap in ordinary A–Z order (`Z -> A`).

Algorithm:

1. Form the eight-letter source sequence
   `S = I || map(succ, I)`.
2. For each `C[j]`, starting at `p = pos_A(C[j])`, take the digits at
   `D[p]`, `D[(p+1)%26]`, `D[(p+2)%26]`. Concatenate all nine digits for
   `j = 0,1,2`, then **discard the ninth digit**, giving eight shifts
   `s[0..8]`.
3. For each `k = 0..7`, set
   `M[k] = A[(pos_A(S[k]) + s[k]) % 26]`.
4. Choose two random filler letters `R[0..2]`. The ten-letter transmitted
   header is `H = M || R`.

The published illustration gives this partial independently checkable case:

```
indicator (I):            KNVP
ordinary +1 (succ(I)):    LOWQ
first ciphertext letters: CMQ
3-digit lookups:          578 326 296
8-digit shift vector:     57832629
source characters:        KNVPLOWQ
masked characters:        RIAVMDQO
sample random header pad: WT
transmitted header:       RIAVMDQOWT   (RIAVM DQOWT)
```

The complete March 16 disguise-key alphabet and digits were transcribed
from Figure 12, and the resulting masked header is checked independently
by `tests/message_indicator_historical.rs` using a YAML fixture parsed with
`noyalib`. This is an **indicator-only** known answer, not a complete-message
wartime ciphertext vector.

### Receiving procedure

1. Identify the correct dated monthly/daily/disguise keys and the sending
   station number through traffic context; the header itself does not
   determine the station.
2. Require at least 10 header characters and 3 genuine ciphertext characters.
   Split first ten header letters from the ciphertext; ignore header letters
   9–10 (1-based), which are random filler.
3. Recompute eight shifts from ciphertext letters 1–3 (i.e. wire positions
   11–13), using the exact same disguise table.
4. Invert the mask:
   `S[k] = A[(pos_A(M[k]) - s[k]).rem_euclid(26)]` for `k = 0..7`.
5. First four unmasked letters give `I`. Validate that the last four equal
   `map(succ, I)`; a mismatch indicates a damaged/incorrect indicator or
   key context. The article says these characters *can* be used to verify,
   not that a historical receiving operator necessarily rejected the message.
6. Set wheel positions 1–4 from `I`, wheels 5–6 from the *sending* station;
   decrypt the genuine ciphertext with the normal core.
7. Distinguish the resulting trailing plaintext used to generate five-letter
   padding from real message contents: **there is no verified in-band
   delimiter or original-length field** in the procedure described here.
   An API must not silently claim exact recovery of original unpadded text.

## Plaintext input conventions

Documented in Antal et al., section 3.4.4:

- Use machine `J` to represent a word space, inserted after each plaintext
  word; literal German letter J is encoded as `II`.
- Write `Ä -> AE`, `Ö -> OE`, `Ü -> UE`.
- Spell numerical values as prescribed German words without separating
  spaces, including `27000 -> SIEBENUNDZWANZIGNULLNULLNULL`.
- Express ordinals in spoken form (e.g. `24.` as `VIERUNDZWANZIGSTE`, adjusted
  to grammatical case and context); do not claim that a context-free number
  converter can produce correct inflected German.
- Decimal monetary notation is rendered in spoken digits with `KOMA` as the
  documented comma word; source example: `RM 75,30` ->
  `REICHSMARK SIEBENFUENF KOMADREINULL` **must not be assumed** as a direct
  character-to-character transform. The published English-language rendering
  of the example is `REICHSMARK SEVENFIVEKOMATHREEZERO`; recheck exact German
  source spelling before enshrining a fixed test fixture.
- A time includes four spoken digits and `UHR`, e.g. `0903 UHR` becomes
  `NULLNEUNNULLDREI UHR`, with historical space-to-J processing afterward.

Keep these **operator/editorial rules** separate from the byte-oriented core
and from any existing general-purpose SG-41 text helper. In particular, do not
apply a blind `J -> II` transform *after* inserting J word separators; the
ordering would corrupt those separators.

## Implemented Rust modules and CLI

The historical procedure is implemented separately from the established
SG-41 wheel and cipher mechanics:

- `src/message.rs`: `DisguiseKey`, `MessageIndicator`, `make_header`,
  `mask_indicator`, `unmask_header`, and `unmask_indicator`.
- `src/procedure.rs`: `DailyKey`, `MonthlyPinTable`, `Quarter`,
  `StationAssignment`, `StationNumbers`, and `historical_config`.
- `src/transmission.rs`: `encipher_message`, `decipher_message`,
  `EncipheredMessage`, `DecipheredMessage`, and `MAX_MESSAGE_LETTERS`.
- `src/error.rs`: centralized errors `MessageError`, `ProcedureError`,
  and `TransmissionError`, derived with `thiserror`.
- `cmd/sg41ctl`: `message-encrypt` and `message-decrypt` commands in addition
  to the original elementary `encrypt` and `decrypt` commands. Historical
  key configuration uses YAML decoded with `noyalib`; command input uses
  the existing `old_crypto_rs::helpers` routines.

The caller supplies the random indicator, header filler, and any plaintext
padding; the library does not implicitly generate random material.
Decryption retains the plaintext corresponding to enciphered padding,
because no in-band original-length field is established.

## Tests and limits of verification

- `tests/message_indicator_historical.rs`: the independently documented
  March 16, 1945 indicator `KNVP`, prefix `CMQ`, shift sequence `57832629`,
  masked text `RIAVMDQO`, and ten-letter header `RIAVMDQOWT`.
- Existing machine known-answer tests verify the SG-41 mechanics for their
  reference settings; they are not full historical message vectors.
- Transmission and CLI tests, including
  `tests/message_transmission_regression.rs`, verify synthetic round trips,
  body limits, grouping, and malformed transmission handling.
- The historical 25/23/24 pin-row selection is supported by the archival
  study's footnote 17 and is implemented by the daily-key configuration.

**Remaining historical evidence gap:** No independently published full
message ciphertext has yet been matched using its complete monthly table,
daily key, station numbers, per-message indicator, and disguise key. The
published `CMQ` prefix proves the indicator computation but does not prove
full end-to-end 1945 interoperability. See `docs/step22-verification.md`.

Historical German operator rules for numbers, inflection, and literal `J`
are documented above; do not assume all such editorial transformations are
automated by the text helper or CLI.
