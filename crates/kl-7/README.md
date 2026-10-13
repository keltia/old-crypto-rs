# kl-7

A typed, cycle-accurate simulation of the TSEC/KL-7 (ADONIS / POLLUX) cipher machine in safe Rust.

## Features
- **8-Rotor Drum**: Cycle-accurate simulation with 36 contact points per rotor and stationary rotor 4.
- **Actuator & Stepping Relay Logic**: Accurate modelling of 7 sensing switch assemblies ($S_a/S_b$) reading notch rings.
- **11 Notch Rings**: Complete implementation of the 11 exchangeable outer notch ring patterns.
- **Multi-pass Re-Entry Maze**: 10 loop-back re-entry paths on endplates for non-linear signal flow.
- **ADONIS & POLLUX**: Support for message key encryption and indicator procedures.
- **YAML Configuration & CLI**: `kl7ctl` CLI tool for terminal encipherment, decipherment, and trace inspection.

## References

- [KL-7 cipher machine](https://en.wikipedia.org/wiki/KL-7)
- [KL-7 extensive description](https://ciphermachinesandcryptology.com/en/kl-7.htm)
- [KL-7 US Cipher Machine](https://www.cryptomuseum.com/crypto/usa/kl7/index.htm)
