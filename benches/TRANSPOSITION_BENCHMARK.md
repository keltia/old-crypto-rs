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
