# SG-41

Historical reconstruction of the German Schlüsselgerät 41.

**Status:** Step 7: typed wheel bank, historical four-phase stepping,
25-bar cage displacement with sixth-wheel inversion, and historical
print-head character conversion. The stateful cipher is not yet implemented;
this crate must not yet be used for message encryption.

See [the technical specification](docs/sg-41.md) and the
[YAML reference fixture](docs/fixtures/sg41-reference.yaml).

Step 8 adds `Sg41Core`, a stateful per-character encipher/decipher engine.
The full 32-letter historical test vector is checked in both directions.
The public `Block` facade, key-file loading and text procedures remain future work.
