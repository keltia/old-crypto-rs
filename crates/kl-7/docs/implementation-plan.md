# TSEC/KL-7 Implementation Plan

## Requirements

### Overview & Goals
The objective is to implement a fully functional, cycle-accurate simulation of the TSEC/KL-7 (ADONIS / POLLUX) cipher machine in a new workspace crate `crates/kl-7`. The implementation follows the design patterns established in `crates/sigaba` and `crates/fialka`, prioritizing type safety, immutability, zero-cost abstractions, clean modular architecture, and partial-commit milestones.

### Scope
- **In Scope**:
  - Full simulation of the 8-rotor drum with 36 contact points.
  - Stationary Rotor 4 and dynamic stepping of Rotors 1, 2, 3, 5, 6, 7, 8.
  - Actuator switch array (7 two-level switches $S_a$ and $S_b$) and stepping solenoid relay logic.
  - 11 exchangeable outer notch rings.
  - 10 loop-back re-entry (re-flexing) contacts on endplates for multi-pass non-linear signal flow.
  - Permutor board (encipher/decipher direction switching).
  - ADONIS and POLLUX operational procedures.
  - Standard reference rotor wiring (Rijmenants default) with YAML support for custom rotor wirings.
  - CLI binary (`kl7ctl`), comprehensive test suite with Known Answer Tests (KAT), and benchmarks.
- **Out of Scope**:
  - Physical hardware interfacing or audio simulation of the mechanical motor.
  - Declassification of historical operational key tables (standard pseudo-random reference wirings will be used).

### Functional Requirements
- **Rotor Model**: 8 rotor slots; 36 contacts (0..35) with bi-directional substitution mapping.
- **Stationary Rotor**: Rotor 4 must remain stationary at its set position.
- **Actuators & Stepping**: Read notch rings 1, 2, 3, 5, 6, 7, 8 via switch contacts and energize the corresponding stepping solenoids according to declassified circuit schematics.
- **Re-Entry Maze**: Route electrical current entering via a 26-letter contact through the rotor drum, bouncing back via 10 loop contacts until exiting at a letter contact.
- **Permutor Switch**: Reverses the direction of entry/exit plates between Encipher and Decipher modes.
- **Text Formatting**: Support standard military message formatting (space conversions, 5-letter blocks, optional letter/figure shift codes).

### Non-Functional Requirements
- **Performance**: High-throughput signal routing using fixed-size arrays (`[u8; 36]`, `[u8; 26]`) and stack allocation without heap allocations on hot encrypt paths.
- **Safety**: 100% safe Rust (`#![forbid(unsafe_code)]`).
- **Compatibility**: Rust 2024 edition, workspace dependency integration.

---

## Technical Design

### Data Models & Contracts
- `Contact36`, `Contact26`, `Position36`, `ReentryWire`
- `Permutation<36>`, `RotorWiring`, `Rotor`
- `NotchRing` (11 distinct cam patterns)
- `ActuatorBank` ($S_a$ sensing switches)
- `SteppingLogic` (solenoid energizing truth table)
- `ReentryMaze` (multi-pass signal propagation across 8 rotors and 10 endplate loops)
- `Kl7Core`, `Kl7Config`, `Kl7`
- `TextNormalizer`, `LetterFigureShift`

---

## Delivery Stages
- **Stage 1**: Crate setup, plan documentation, and core rotor primitives.
- **Stage 2**: Actuator switch matrix and stepping logic.
- **Stage 3**: Rotor drum re-entry maze and electrical circuit engine.
- **Stage 4**: Machine state, permutor board, and operational procedures.
- **Stage 5**: Text processing, YAML configuration, and CLI tool (`kl7ctl`).
- **Stage 6**: Known Answer Tests (KAT), benchmarks, and workspace documentation.
