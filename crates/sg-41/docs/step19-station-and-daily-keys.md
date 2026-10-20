# Step 19 — Station assignments and daily-key setup

Historical basis: Antal, Dahlke and Jahn, *Revealing secrets from WWII: the original German instructions of Schlüsselgerät 41*, Cryptologia (2025), DOI 10.1080/01611194.2025.2557311, section 3.4 and discussion section 4.4.

## Confirmed rules

- A station receives two two-digit identifiers, for windows of wheels 5 and 6. In transmission they belong to the sender; in reception the same sender identifiers must be used.
- Assignments change on January 1, April 1, July 1 and October 1. Assignment values must be supplied, not guessed from dates.
- The four-letter random message indicator initializes wheels 1–4; the two station numbers initialize wheels 5–6.
- A six-letter daily key selects one of the 26 labeled 25-bit monthly-table rows for each wheel; each wheel uses the first 25, 23 or 24 settings according to its physical length.
- Wheel five markings are 01–24; wheel six markings are the irregular 00–57 values implemented in `types.rs`. Use the existing validation.

## Design limits

`MonthlyPinTable` accepts already transcribed, 25-bit rows in the source monthly-table order. Historical image Figure 11 remains to be independently transcribed into a YAML fixture; no fabricated March monthly pin table is included here. Thus Step 19 currently validates *the procedure*, not a fully sourced March 1945 wheel-pin known-answer.

`Quarter` describes validity, not a universal station-number derivation. The source says stations keep the same assignment across different networks, but provides no complete registry. No station directory or date-dependent automatic identifier generation is claimed.

For any operational historical message, the daily key and disguise key are date-specific, and a sending station assignment valid for the message quarter is also required. Step 20 can bind these inputs when constructing an end-to-end message API.

## Integration

Add `mod procedure;` to `src/lib.rs` and export `DailyKey`, `MonthlyPinTable`, `Quarter`, `StationAssignment`, `StationNumbers`, and `historical_config`. Add `ProcedureError` to `src/error.rs`. No Cargo manifest changes.
