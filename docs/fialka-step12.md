# Fialka Step 12 - independent reference validation

Step 12 is a validation milestone rather than a new cipher feature.

## Result

The independent cross-check found one missing fixed machine component in the
Step-10 signal path: the 30-way substitution between the keyboard/print contact
system and the punched-card reader.

Crypto Museum publishes the keyboard-to-card table on its Fialka wiring page.
H. Hafting's independently developed Fialka simulator uses the same mapping:

```text
keyboard: А Б В Г Д Е Ж З И К Л М Н О П Р С Т У Ф Х Ц Ч Ш Щ Ы Ь Ю Я Й
card:     С Щ Й О Ы Х Е У А П Я Ф Г Ю Ш Б Ц Ч Т М Ж Д Ь З К И Р Н Л В
```

The corrected normal 30-contact path is therefore:

```text
keyboard
  -> fixed keyboard substitution
  -> punched-card commutator
  -> fixed entry disc
  -> rotors 10..1
  -> reflector / three-point circuit
  -> rotors 1..10
  -> inverse entry disc
  -> inverse punched-card commutator
  -> inverse fixed keyboard substitution
  -> printer/output
```

The reflector plaintext-enable path remains special: it outputs the original
keyboard symbol directly and therefore bypasses the normal return path.

## Reference status

A complete public historical tuple containing *all* of the following has not
been located yet:

- rotor series and all ten rotor bodies;
- core identities, side and insertion settings;
- ring settings;
- punched-card contents;
- starting rotor positions;
- plaintext;
- corresponding ciphertext from a real machine.

The GDR M-125 operations manual does provide an official machine-test procedure
and the testing text (Figure 13), and requires enciphering and deciphering that
text under the valid daily key with all rotor positions initially set to `А`.
It does not print the resulting ciphertext, so it cannot by itself supply a
known-answer ciphertext fixture.

Consequently this step does **not** label a self-generated ciphertext as a
historical KAT.  Instead it adds an independently published fixed-wiring fixture
and corrects the complete signal path discovered through that cross-check.

## Sources

- Crypto Museum, Fialka Wiring:
  https://www.cryptomuseum.com/crypto/fialka/wiring.htm
- H. Hafting, independent Fialka simulator configuration:
  https://github.com/Hafting/enigma/blob/master/fialka-m125
- GDR M-125 operations manual, English translation, sections 5.2-5.3 and
  Figure 13:
  https://www.cryptomuseum.com/crypto/fialka/files/fialka_M125_EN.pdf
