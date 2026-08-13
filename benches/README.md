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
cargo bench --bench=ciphers --features fialka

Timer precision: 100 ns
ciphers                            fastest       │ slowest       │ median        │ mean          │ samples │ iters
├─ b0_encryption                                 │               │               │               │         │
│  ├─ b01_caesar                   57.62 ns      │ 103.7 ns      │ 58.01 ns      │ 58.93 ns      │ 100     │ 25600
│  ├─ b02_vigenere                 237.3 ns      │ 301.3 ns      │ 240.4 ns      │ 240.5 ns      │ 100     │ 6400
│  ├─ b03_autokey                  227.9 ns      │ 295.1 ns      │ 229.4 ns      │ 231.3 ns      │ 100     │ 6400
│  ├─ b04_autocrypt                224.8 ns      │ 584.1 ns      │ 334.1 ns      │ 311 ns        │ 100     │ 3200
│  ├─ b05_square                   31.64 ns      │ 51.37 ns      │ 32.32 ns      │ 33.53 ns      │ 100     │ 51200
│  ├─ b06_playfair                 637.3 ns      │ 906 ns        │ 656 ns        │ 656.5 ns      │ 100     │ 1600
│  ├─ b07_transposition            31.25 ns      │ 39.06 ns      │ 32.23 ns      │ 32.24 ns      │ 100     │ 51200
│  ├─ b08_irregular_transposition  156 ns        │ 221.6 ns      │ 157.6 ns      │ 158 ns        │ 100     │ 6400
│  ├─ b09_straddling               45.51 ns      │ 45.9 ns       │ 45.9 ns       │ 45.76 ns      │ 100     │ 25600
│  ├─ b10_adfgvx                   60.74 ns      │ 190.8 ns      │ 61.13 ns      │ 63.39 ns      │ 100     │ 25600
│  ├─ b11_nihilist                 101.3 ns      │ 216.2 ns      │ 105.2 ns      │ 110.7 ns      │ 100     │ 12800
│  ├─ b12_vic                      468.5 ns      │ 643.5 ns      │ 543.5 ns      │ 523.9 ns      │ 100     │ 3200
│  ├─ b13_secom                    406 ns        │ 737.3 ns      │ 409.1 ns      │ 489.6 ns      │ 100     │ 3200
│  ├─ b14_chaocipher               2.424 µs      │ 18.24 µs      │ 2.474 µs      │ 2.635 µs      │ 100     │ 400
│  ├─ b15_solitaire                4.799 µs      │ 6.449 µs      │ 4.849 µs      │ 4.92 µs       │ 100     │ 200
│  ├─ b16_wheatstone               274.8 ns      │ 337.3 ns      │ 276.3 ns      │ 276.2 ns      │ 100     │ 6400
│  ├─ b17_sigaba                   1.362 µs      │ 1.537 µs      │ 1.374 µs      │ 1.376 µs      │ 100     │ 800
│  ╰─ b18_fialka                   8.499 µs      │ 22.79 µs      │ 8.599 µs      │ 8.789 µs      │ 100     │ 100
╰─ b1_decryption                                 │               │               │               │         │
   ├─ b01_caesar                   61.13 ns      │ 74.41 ns      │ 61.52 ns      │ 61.55 ns      │ 100     │ 25600
   ├─ b02_vigenere                 274.8 ns      │ 346.6 ns      │ 277.9 ns      │ 279.4 ns      │ 100     │ 6400
   ├─ b03_autokey                  281 ns        │ 563.8 ns      │ 291.9 ns      │ 301.1 ns      │ 100     │ 6400
   ├─ b04_autocrypt                240.4 ns      │ 501.3 ns      │ 241.9 ns      │ 246.9 ns      │ 100     │ 6400
   ├─ b05_square                   31.45 ns      │ 39.65 ns      │ 31.64 ns      │ 31.87 ns      │ 100     │ 51200
   ├─ b06_playfair                 277.9 ns      │ 582.6 ns      │ 282.6 ns      │ 288.2 ns      │ 100     │ 6400
   ├─ b07_transposition            23.44 ns      │ 31.45 ns      │ 23.63 ns      │ 23.81 ns      │ 100     │ 51200
   ├─ b08_irregular_transposition  240.4 ns      │ 249.8 ns      │ 241.9 ns      │ 243.9 ns      │ 100     │ 6400
   ├─ b09_straddling               66.99 ns      │ 109.9 ns      │ 67.38 ns      │ 67.97 ns      │ 100     │ 25600
   ├─ b10_adfgvx                   70.51 ns      │ 90.04 ns      │ 71.29 ns      │ 71.76 ns      │ 100     │ 25600
   ├─ b11_nihilist                 121.6 ns      │ 154.4 ns      │ 122.4 ns      │ 123 ns        │ 100     │ 12800
   ├─ b12_vic                      631 ns        │ 1.568 µs      │ 643.5 ns      │ 656.9 ns      │ 100     │ 1600
   ├─ b13_secom                    402.9 ns      │ 1.034 µs      │ 409.1 ns      │ 438 ns        │ 100     │ 3200
   ├─ b14_chaocipher               2.312 µs      │ 5.437 µs      │ 2.324 µs      │ 2.371 µs      │ 100     │ 800
   ├─ b15_solitaire                4.849 µs      │ 14.84 µs      │ 5.099 µs      │ 5.388 µs      │ 100     │ 200
   ├─ b16_wheatstone               201.3 ns      │ 266.9 ns      │ 202.9 ns      │ 203.6 ns      │ 100     │ 6400
   ├─ b17_sigaba                   1.412 µs      │ 5.124 µs      │ 1.762 µs      │ 1.794 µs      │ 100     │ 800
   ╰─ b18_fialka                   8.549 µs      │ 14.59 µs      │ 8.549 µs      │ 8.653 µs      │ 100     │ 200
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


