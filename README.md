# bharatpii

Find and redact Indian personal data in text: Aadhaar, PAN, GSTIN, UPI IDs,
mobile numbers, vehicle registrations and more. Pure Python, no dependencies,
Python 3.10+.

General-purpose PII tools handle emails and US-style numbers well, but they
mostly don't know Indian formats. A regex for "12 digits" flags every order ID
in your logs. bharatpii checks the check digits that Indian IDs carry
(Verhoeff for Aadhaar, mod-36 for GSTIN, Luhn for cards) and looks for
keywords like "aadhaar", "a/c" or "आधार" near a match before it reports
anything ambiguous.

```
pip install bharatpii
```

## Command line

```
$ bharatpii scan examples/customer.txt
examples/customer.txt:2:10: aadhaar XXXX XXXX 8697 (0.90)
examples/customer.txt:3:6: pan XXXXXX234F (0.99)
examples/customer.txt:4:8: gstin XXXXXXXXXXXT2ZM (0.99)
examples/customer.txt:5:9: phone +XX XXXXX X3210 (0.99)
examples/customer.txt:6:6: upi rXXXXXXXXX@okaxis (0.99)
examples/customer.txt:7:11: bank_account XXXXXXXXXX6789 (0.75)
examples/customer.txt:7:32: ifsc XXXXXXX1234 (0.85)
examples/customer.txt:8:10: vehicle XX XX XX 1234 (0.95)

8 finding(s) in 1 file(s)
```

`scan` exits with 1 when it finds something, so it works in CI and pre-commit.
Values are partially masked in the output so the scan itself doesn't leak data
into CI logs. Pass `--show` to see full values, or `--json` for machine output.

```
$ bharatpii redact examples/customer.txt --style partial
Customer: Ravi Kumar
Aadhaar: XXXX XXXX 8697
PAN: XXXXXX234F
...
Order 4521 shipped on 2026-11-21, total Rs 2,499.
```

Other options: `-o out.txt`, `-i` (in place), `--kinds aadhaar,pan`,
`--min-confidence 0.8`, `-I` (also match lowercase IDs). `bharatpii kinds` lists
every detector.

## Python

```python
from bharatpii import scan, redact

text = "Aadhaar 3588 1399 8697, call +91 98765 43210"

for m in scan(text):
    print(m.kind, m.value, m.start, m.end, m.confidence)
# aadhaar 3588 1399 8697 8 22 0.9
# phone +91 98765 43210 29 44 0.99

redact(text)                    # 'Aadhaar [AADHAAR], call [PHONE]'
redact(text, style="partial")   # 'Aadhaar XXXX XXXX 8697, call +XX XXXXX X3210'
redact(text, style="mask")      # 'Aadhaar XXXX XXXX XXXX, call +XX XXXXX XXXXX'
redact(text, style="hash")      # 'Aadhaar [AADHAAR:e786c1b9d1], call [PHONE:1a6f46a8fa]' (keyed, see below)
```

Use `Scanner` to keep settings:

```python
from bharatpii import Scanner

s = Scanner(kinds=["aadhaar", "pan", "phone"], min_confidence=0.8, ignore_case=True)
s.contains_pii(user_message)
```

### Redacting logs

```python
import logging
from bharatpii import RedactingFilter

handler = logging.StreamHandler()
handler.addFilter(RedactingFilter(style="partial"))
logging.basicConfig(level=logging.INFO, handlers=[handler])

logging.info("payment from %s", "9876543210@ybl")
# payment from 9XXXXXXXXX@ybl
```

The filter redacts the formatted message and any exception traceback.

### Test data

`bharatpii.fake` generates checksum-valid values for fixtures:

```python
from bharatpii.fake import Faker

f = Faker(seed=42)
f.aadhaar(), f.pan(), f.gstin(state="27"), f.phone(), f.upi(), f.card(), f.vehicle()
```

A random valid-looking Aadhaar or phone number can still belong to a real
person. Use these as test fixtures only.

## What it detects

| kind | format | validation |
|---|---|---|
| `aadhaar` | 12 digits, groups of 4 optional | first digit 2-9, Verhoeff checksum |
| `aadhaar_vid` | 16 digits | Verhoeff; needs keyword "VID" |
| `pan` | `AAAAA9999A` | 4th letter must be a valid holder type |
| `gstin` | 15 chars | state code 01-38/97/99, embedded PAN, check character |
| `ifsc` | `AAAA0XXXXXX` | 5th char is 0 |
| `upi` | `name@handle` | known handles (okaxis, ybl, paytm...) score higher; emails excluded |
| `email` | standard | |
| `phone` | `9876543210`, `+91 98765 43210`, `098765 43210`, `987 654 3210` | starts 6-9 |
| `card` | 13-19 digits | Luhn |
| `vehicle` | `MH 12 AB 1234`, `22 BH 1234 AA` | real state codes; BH year ≥ 21 |
| `driving_licence` | `MH14 20110062821` | state code, issue year not in future |
| `passport` | `J8369854` | needs keyword |
| `voter_id` | `ABC1234567` | needs keyword |
| `bank_account` | 9-18 digits | needs keyword ("account", "a/c", "खाता") |
| `pincode` | `560001` | needs keyword |

## How matching works

1. Each detector's regex finds candidates.
2. A score function rejects candidates that fail validation (bad checksum,
   wrong state code, repeated digits like `9999999999`) and gives the rest a
   base confidence.
3. If a keyword for that kind appears within 40 characters before or 20 after
   the match, confidence goes up by 0.15. Kinds marked "needs keyword" are
   dropped without one.
4. Where matches overlap, the one with its own keyword nearby wins, then the
   higher confidence, then the longer span. So a GSTIN wins over the PAN inside
   it, and `a/c 50100123456789` counts as an account number even though it
   happens to pass the card checksum.

The default threshold is 0.5. Use 0.8 or higher if false positives cost more
than misses.

## Limitations

- **Bare 12-digit numbers.** About 1 in 10 random 12-digit numbers starting
  2-9 passes the Verhoeff check, so an order ID can be reported as an Aadhaar
  (confidence 0.75 without a keyword). Raise `--min-confidence` to 0.8 to only
  report Aadhaar numbers that have a keyword nearby.
- **No checksum** exists (or is public) for PAN, IFSC, passport, voter ID or
  vehicle numbers, so these rely on format and keywords.
- **Names and addresses** are not detected. That needs NER (for example
  Presidio or spaCy); bharatpii covers structured identifiers only.
- **Uppercase by default** for PAN, GSTIN, IFSC, passport, voter ID and DL,
  because official formats are uppercase and it's about 4x faster. Use
  `ignore_case=True` / `-I` for user-typed input. Vehicle plates are always
  uppercase-only, so English phrases like "or 12 1234" aren't flagged.
- **Hash style** uses HMAC-SHA256 with a random key per `Scanner`. Aadhaar has
  only about 10^11 possible values, so a plain unkeyed hash could be reversed by
  brute force. Pass `key=` to get the same hashes across runs, and keep that
  key secret.
- **Speed.** About 1.7 MB/s on log-like text and over 60 MB/s on text without
  digits; about 130 µs to redact one log line (`python scripts/benchmark.py`,
  laptop CPU). That's fine for logs, chat messages and CI scans. For
  multi-gigabyte data dumps, run it in parallel.

## pre-commit

```yaml
repos:
  - repo: https://github.com/Pratix005/bharatpii
    rev: v0.1.1
    hooks:
      - id: bharatpii
```

## Development

```
git clone https://github.com/Pratix005/bharatpii
cd bharatpii
python -m venv .venv && .venv/bin/pip install -e ".[dev]"   # Windows: .venv\Scripts\pip
pytest
```

New detectors and more UPI handles are welcome; see
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0
