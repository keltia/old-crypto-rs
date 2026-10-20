# SG-41 historical message procedures

Status: research-backed specification draft (2026-10-20). No code changes yet.

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
   six wheels together have 144 pins; applying a row to a wheel must respect
   that wheel's actual pin count and the documentary table layout. Do *not*
   assume that all wheels have 25 pins.
2. **Daily key (`Tagesschlüssel`) — documented.** Six letters select six rows
   of the monthly table, one for each wheel in order. Reconfigure pin settings
   daily. The example for 16 March 1945 uses `ACHUKW`.
3. **Disguise key (`Tarnschlüssel`) — documented.** For the day, a permutation
   of A–Z with a position-aligned length-26 sequence of digits from 1–9
   (without zero). Duplicates are necessarily allowed in the digits. This is
   *not* a 26-digit permutation. Its original, exact 16 March 1945 sequences
   must be transcribed from the source illustration before a full independent
   worked-vector test can be added.
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

**Open framing nuance:** The article specifies 600 letters as the maximum
message length and describes ciphertext padding. Verify against the original
manual whether the cap counts pre-padding cipher letters alone, any other
operational framing, and/or the ten-letter indicator header. Do not reject
boundary lengths on an unverified interpretation.

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

The **masked character** fixture depends on the exact 16 March 1945
scrambled alphabet. Its full historical alphabet and digit row must be
verified/transcribed from the paper's Figure 12 / archived key sheet, not
reverse-engineered to force the expected output.

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

## Proposed Rust API boundaries (design only)

Keep a new operational module, for example `message.rs`, independent of the
rotor/print-head mechanisms. Prefer existing core helpers (especially
`old_crypto_rs::helpers::text`) wherever semantics match; avoid duplication.

- `MonthlyTable`: validated 26 pin-pattern rows with explicit wheel slicing
  rules; exact storage decision after inspecting current SG-41 types.
- `DailyKey`: six row selectors plus the daily disguise key.
- `DisguiseKey`: validated `[u8; 26]` letter permutation and `[u8; 26]`
  digit row (digits 1–9, repetitions allowed).
- `StationNumber`: validated display markings for wheels 5 and 6, mapped by
  existing wheel-position types instead of guessed modular arithmetic.
- `MessageIndicator`: four A–Z letters; randomness supplied by caller or a
  pluggable source rather than new mandatory dependencies.
- Pure `mask_indicator` / `unmask_indicator` functions returning a structured
  error (using `thiserror`) for malformed key tables, illegal letters, short
  payloads and failed consistency checks.
- An explicit high-level `encipher_message` / `decipher_message` wrapper
  consuming daily key, sender station, indicator and padding input, while
  leaving existing `Sg41Core`, `Sg41Config` and `Block` unchanged.
- Decryption results should retain the padding-containing plaintext and
  optionally expose a caller-supplied original length, if appropriate. Do not
  infer that length or strip guessed padding.

## Test plan and open verification items

1. Transcribe the **actual** March 16 disguise alphabet and digit row, and
   verify the sample `KNVP / CMQ -> RIAVMDQOWT` end-to-end. Preserve the
   complete historical key sheet as attributed test fixture if licensing
   permits; otherwise publish an appropriately described derived fixture.
2. Round-trip a fixed fabricated valid disguise key over numerous indicators
   and three-letter prefixes, including wraparound at positions 25/0/1.
3. Verify that `D` can contain duplicate digits, that zero is forbidden,
   and that `A` is a permutation with no duplicate letters.
4. Validate `S[4..8] == succ(S[0..4])` during unmasking; test tampering and
   wrong daily key. Note that not every substitution must be detected.
5. Verify the historical mapping of wheel 5 display `18` and wheel 6 display
   `37` to positions in the current six-wheel model; verify their reversal
   on receiving instead of assuming ordinary wheel indexes.
6. Ensure encrypted *padding* changes wheel stepping; test 5-group formatting,
   complete header length, boundary 600, short ciphertext, and multipart
   handling. Confirm what the 600-letter limit actually counts.
7. Test input-layer `J` handling and `II` literal encoding carefully,
   including words containing J; historical spellings and suffixes require
   explicit operator-provided normalized text or separate, tested rules.
8. Compare against the Antal et al. Appendix B example and original document
   scans before declaring full historical interoperability.

**Stage gate:** do not implement the higher-level API until the exact archive
mask table and the current SG-41 typed wheel/config interfaces have been
checked. The machine-cipher known-answer tests must remain unchanged.
