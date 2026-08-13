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
│  ├─ b01_caesar                   67.77 ns      │ 84.96 ns      │ 68.16 ns      │ 69.72 ns      │ 100     │ 25600
│  ├─ b02_vigenere                 240.4 ns      │ 577.9 ns      │ 412.3 ns      │ 394.9 ns      │ 100     │ 3200
│  ├─ b03_autokey                  241.9 ns      │ 371.6 ns      │ 247.4 ns      │ 250.1 ns      │ 100     │ 6400
│  ├─ b04_autocrypt                218.5 ns      │ 293.5 ns      │ 218.5 ns      │ 221.3 ns      │ 100     │ 6400
│  ├─ b05_square                   31.06 ns      │ 39.45 ns      │ 31.45 ns      │ 31.6 ns       │ 100     │ 51200
│  ├─ b06_playfair                 624.8 ns      │ 968.5 ns      │ 662.3 ns      │ 673.6 ns      │ 100     │ 1600
│  ├─ b07_transposition            17.87 ns      │ 32.52 ns      │ 18.65 ns      │ 20.1 ns       │ 100     │ 102400
│  ├─ b08_irregular_transposition  163.8 ns      │ 241.9 ns      │ 174.8 ns      │ 175.6 ns      │ 100     │ 6400
│  ├─ b09_straddling               37.11 ns      │ 59.18 ns      │ 37.31 ns      │ 39.54 ns      │ 100     │ 51200
│  ├─ b10_adfgvx                   81.84 ns      │ 167.7 ns      │ 82.62 ns      │ 97.97 ns      │ 100     │ 12800
│  ├─ b11_nihilist                 83.4 ns       │ 154.4 ns      │ 122.4 ns      │ 108.7 ns      │ 100     │ 12800
│  ├─ b12_vic                      437.3 ns      │ 571.6 ns      │ 518.5 ns      │ 497.1 ns      │ 100     │ 3200
│  ├─ b13_secom                    409.1 ns      │ 1.615 µs      │ 418.5 ns      │ 449.3 ns      │ 100     │ 3200
│  ├─ b14_chaocipher               2.399 µs      │ 2.524 µs      │ 2.424 µs      │ 2.426 µs      │ 100     │ 400
│  ├─ b15_solitaire                5.249 µs      │ 11.99 µs      │ 5.399 µs      │ 5.534 µs      │ 100     │ 200
│  ├─ b16_wheatstone               284.1 ns      │ 434.1 ns      │ 318.5 ns      │ 331.2 ns      │ 100     │ 3200
│  ├─ b17_sigaba                   10.19 µs      │ 15.09 µs      │ 10.29 µs      │ 10.37 µs      │ 100     │ 100
│  ╰─ b18_fialka                   8.299 µs      │ 12.89 µs      │ 8.299 µs      │ 8.375 µs      │ 100     │ 100
╰─ b1_decryption                                 │               │               │               │         │
   ├─ b01_caesar                   68.56 ns      │ 102.9 ns      │ 68.95 ns      │ 69.4 ns       │ 100     │ 25600
   ├─ b02_vigenere                 277.9 ns      │ 552.9 ns      │ 360.7 ns      │ 383.1 ns      │ 100     │ 3200
   ├─ b03_autokey                  521.6 ns      │ 1.074 µs      │ 587.3 ns      │ 618.4 ns      │ 100     │ 3200
   ├─ b04_autocrypt                232.6 ns      │ 374.8 ns      │ 232.6 ns      │ 240.2 ns      │ 100     │ 6400
   ├─ b05_square                   30.66 ns      │ 37.5 ns       │ 30.66 ns      │ 30.97 ns      │ 100     │ 51200
   ├─ b06_playfair                 268.5 ns      │ 518.5 ns      │ 393.5 ns      │ 344.5 ns      │ 100     │ 3200
   ├─ b07_transposition            22.85 ns      │ 172.8 ns      │ 23.05 ns      │ 24.96 ns      │ 100     │ 51200
   ├─ b08_irregular_transposition  240.4 ns      │ 310.7 ns      │ 246.6 ns      │ 247.4 ns      │ 100     │ 6400
   ├─ b09_straddling               61.91 ns      │ 79.1 ns       │ 62.7 ns       │ 63.13 ns      │ 100     │ 25600
   ├─ b10_adfgvx                   74.02 ns      │ 126.3 ns      │ 75.59 ns      │ 76.22 ns      │ 100     │ 25600
   ├─ b11_nihilist                 116.9 ns      │ 152.1 ns      │ 120.1 ns      │ 121 ns        │ 100     │ 12800
   ├─ b12_vic                      599.8 ns      │ 956 ns        │ 618.5 ns      │ 732.6 ns      │ 100     │ 1600
   ├─ b13_secom                    402.9 ns      │ 534.1 ns      │ 409.1 ns      │ 410.7 ns      │ 100     │ 3200
   ├─ b14_chaocipher               2.424 µs      │ 3.474 µs      │ 2.449 µs      │ 2.493 µs      │ 100     │ 400
   ├─ b15_solitaire                5.049 µs      │ 8.599 µs      │ 5.199 µs      │ 5.271 µs      │ 100     │ 200
   ├─ b16_wheatstone               177.9 ns      │ 245.1 ns      │ 179.4 ns      │ 181 ns        │ 100     │ 6400
   ├─ b17_sigaba                   10.29 µs      │ 41.99 µs      │ 17.79 µs      │ 14.79 µs      │ 100     │ 100
   ╰─ b18_fialka                   8.249 µs      │ 10.34 µs      │ 8.349 µs      │ 8.49 µs       │ 100     │ 200```

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


