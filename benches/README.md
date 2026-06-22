# Transposition Cipher Benchmark Results

This benchmark compares the performance of three transposition cipher implementations:
- **Regular** (`Transposition`): Standard columnar transposition
- **Irregular** (`IrregularTransposition`): VIC-style with triangular areas
- **Disrupted** (`Disrupted<P>`): Generic implementation with pluggable masking policies

## Correctness Verification

All implementations are verified to produce correct results:

```
✓ All transposition implementations verified correct
  Regular:          CWTDAATTAAKN → ATTACKATDAWN
  Irregular:        TWKCATTAAADN → ATTACKATDAWN
  Disrupted NoMask: CWTDAATTAAKN → ATTACKATDAWN  (matches Regular)
  Disrupted Vic:    TWKCATTAAADN → ATTACKATDAWN  (matches Irregular)
  Disrupted Secom:  ADTAACTKATWN → ATTACKATDAWN  (unique pattern)
```

## Performance Results

Key: SUBWAY (6 characters)

### Short Text (12 bytes: "ATTACKATDAWN")

| Implementation        | Encrypt   | Decrypt   |
|----------------------|-----------|-----------|
| Regular              | ~15 ns    | ~18 ns    |
| Irregular            | ~67 ns    | ~108 ns   |
| Disrupted NoMask     | ~73 ns    | ~83 ns    |
| Disrupted VicMask    | ~80 ns    | ~92 ns    |
| Disrupted SecomMask  | ~74 ns    | ~107 ns   |

### Long Text (35 bytes: "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG")

| Implementation        | Encrypt   | Decrypt   |
|----------------------|-----------|-----------|
| Regular              | ~26 ns    | ~29 ns    |
| Irregular            | ~155 ns   | ~236 ns   |
| Disrupted NoMask     | ~141 ns   | ~162 ns   |
| Disrupted VicMask    | ~164 ns   | ~177 ns   |
| Disrupted SecomMask  | ~156 ns   | ~183 ns   |

## Analysis

1. **Regular Transposition** is significantly faster (~5-8x) than masked variants because:
   - No mask array creation or checking
   - Single-phase grid filling
   - Simpler logic path

2. **Disrupted vs Irregular** comparison:
   - `Disrupted<VicMask>` has comparable performance to `IrregularTransposition`
   - The generic approach adds minimal overhead (~10-20%)
   - Benefits: flexibility to use any masking policy

3. **Masking Policy Impact**:
   - NoMask: Fastest disrupted variant (no actual masking work)
   - VicMask: Slightly slower (triangular area computation)
   - SecomMask: Similar to VicMask despite more complex logic

4. **Scaling**: All implementations scale roughly linearly with input size

## Recommendations

- **Use `Transposition`** for simple columnar transposition (fastest)
- **Use `IrregularTransposition`** for VIC-style cipher (optimized for this specific pattern)
- **Use `Disrupted<P>`** when you need:
  - Custom masking patterns
  - Flexibility to switch policies at compile-time
  - Experimentation with different disruption strategies

## Running the Benchmark

```bash
cargo bench --bench transposition
```

To run with specific filters:

```bash
# Only encryption benchmarks
cargo bench --bench transposition encrypt

# Only short text benchmarks
cargo bench --bench transposition short

# Specific implementation
cargo bench --bench transposition regular
```

# Ciphers Benchmark Results

PC, AMD 7700X, 32 GB RAM, 500 GB M2 SSD, Win 11 25H2

```text
cargo bench --bench=ciphers

Timer precision: 100 ns
ciphers                            fastest       │ slowest       │ median        │ mean          │ samples │ iters
├─ b0_encryption                                 │               │               │               │         │
│  ├─ b01_caesar                   20.89 ns      │ 27.14 ns      │ 20.89 ns      │ 21.07 ns      │ 100     │ 51200
│  ├─ b02_vigenere                 199.8 ns      │ 13.19 µs      │ 299.8 ns      │ 432.8 ns      │ 100     │ 100
│  ├─ b03_autokey                  134.9 ns      │ 173.2 ns      │ 136.5 ns      │ 137.3 ns      │ 100     │ 12800
│  ├─ b04_autocrypt                56.44 ns      │ 441.2 ns      │ 56.83 ns      │ 61.26 ns      │ 100     │ 25600
│  ├─ b05_square                   32.02 ns      │ 57.22 ns      │ 32.22 ns      │ 33.29 ns      │ 100     │ 51200
│  ├─ b06_playfair                 393.5 ns      │ 1.977 µs      │ 496.6 ns      │ 584.3 ns      │ 100     │ 3200
│  ├─ b07_transposition            17.96 ns      │ 36.12 ns      │ 17.96 ns      │ 18.29 ns      │ 100     │ 51200
│  ├─ b08_irregular_transposition  155.2 ns      │ 220.1 ns      │ 156.8 ns      │ 158.9 ns      │ 100     │ 12800
│  ├─ b09_straddling               38.86 ns      │ 60.73 ns      │ 39.25 ns      │ 39.42 ns      │ 100     │ 25600
│  ├─ b10_adfgvx                   59.95 ns      │ 95.5 ns       │ 60.73 ns      │ 61.52 ns      │ 100     │ 25600
│  ├─ b11_nihilist                 81.83 ns      │ 509.9 ns      │ 82.61 ns      │ 97.6 ns       │ 100     │ 12800
│  ├─ b12_vic                      459.1 ns      │ 643.5 ns      │ 518.5 ns      │ 505.3 ns      │ 100     │ 3200
│  ├─ b13_secom                    362.3 ns      │ 1.912 µs      │ 374.8 ns      │ 394.4 ns      │ 100     │ 800
│  ├─ b14_chaocipher               1.724 µs      │ 2.262 µs      │ 1.762 µs      │ 1.757 µs      │ 100     │ 800
│  ├─ b15_solitaire                4.599 µs      │ 7.299 µs      │ 4.899 µs      │ 4.94 µs       │ 100     │ 200
│  ╰─ b16_wheatstone               290.4 ns      │ 501.3 ns      │ 290.4 ns      │ 296.3 ns      │ 100     │ 6400
╰─ b1_decryption                                 │               │               │               │         │
   ├─ b01_caesar                   20.69 ns      │ 20.89 ns      │ 20.69 ns      │ 20.72 ns      │ 100     │ 51200
   ├─ b02_vigenere                 160.7 ns      │ 345.1 ns      │ 162.3 ns      │ 164.8 ns      │ 100     │ 6400
   ├─ b03_autokey                  210.7 ns      │ 276.3 ns      │ 213.8 ns      │ 213.8 ns      │ 100     │ 6400
   ├─ b04_autocrypt                75.19 ns      │ 281 ns        │ 87.49 ns      │ 92.66 ns      │ 100     │ 25600
   ├─ b05_square                   32.02 ns      │ 43.55 ns      │ 32.22 ns      │ 32.64 ns      │ 100     │ 51200
   ├─ b06_playfair                 53.31 ns      │ 80.26 ns      │ 53.7 ns       │ 54.68 ns      │ 100     │ 25600
   ├─ b07_transposition            26.36 ns      │ 39.44 ns      │ 26.55 ns      │ 26.95 ns      │ 100     │ 51200
   ├─ b08_irregular_transposition  240.4 ns      │ 324.8 ns      │ 241.9 ns      │ 243.7 ns      │ 100     │ 6400
   ├─ b09_straddling               63.08 ns      │ 109.1 ns      │ 63.86 ns      │ 66.02 ns      │ 100     │ 25600
   ├─ b10_adfgvx                   75.19 ns      │ 225.9 ns      │ 76.75 ns      │ 82.48 ns      │ 100     │ 25600
   ├─ b11_nihilist                 131 ns        │ 281 ns        │ 132.6 ns      │ 136 ns        │ 100     │ 6400
   ├─ b12_vic                      509.1 ns      │ 809.1 ns      │ 515.4 ns      │ 519.7 ns      │ 100     │ 3200
   ├─ b13_secom                    399.8 ns      │ 777.9 ns      │ 409.1 ns      │ 413.9 ns      │ 100     │ 3200
   ├─ b14_chaocipher               1.724 µs      │ 2.249 µs      │ 1.737 µs      │ 1.737 µs      │ 100     │ 800
   ├─ b15_solitaire                4.749 µs      │ 9.749 µs      │ 4.849 µs      │ 4.975 µs      │ 100     │ 200
   ╰─ b16_wheatstone               202.9 ns      │ 515.4 ns      │ 231 ns        │ 276.7 ns      │ 100     │ 3200
```

# Helpers Benchmark Results

There is a separate benchmark for internal (aka helpers) functions:

```text
Timer precision: 100 ns
helpers                     fastest       │ slowest       │ median        │ mean          │ samples │ iters
├─ condense                               │               │               │               │         │
│  ├─ bench_condense        712.3 ns      │ 1.262 µs      │ 724.8 ns      │ 748.6 ns      │ 100     │ 1600
│  ╰─ bench_condense_str    53.71 ns      │ 70.51 ns      │ 54.1 ns       │ 54.32 ns      │ 100     │ 25600
├─ fix_double                             │               │               │               │         │
│  ├─ bench_double_aligned  206 ns        │ 329.4 ns      │ 207.6 ns      │ 226.4 ns      │ 100     │ 6400
│  ├─ bench_expand          85.74 ns      │ 182.6 ns      │ 88.09 ns      │ 117.1 ns      │ 100     │ 12800
│  ╰─ bench_fix_double      111.5 ns      │ 132.6 ns      │ 112.3 ns      │ 112.9 ns      │ 100     │ 12800
╰─ shuffle                                │               │               │               │         │
   ├─ bench_shuffle         138.8 ns      │ 228.7 ns      │ 141.9 ns      │ 142.7 ns      │ 100     │ 12800
   ╰─ bench_transp_shuffle  154.4 ns      │ 291.9 ns      │ 157.6 ns      │ 176.3 ns      │ 100     │ 6400
```


