# Contributing

## Setup

```
python -m venv .venv
.venv/bin/pip install -e ".[dev]"     # Windows: .venv\Scripts\pip
pytest
```

## Adding a detector

Detectors live in `src/aadhaarguard/detectors.py`. Each one needs:

- a regex. Start it with `_first(...)` instead of a leading lookbehind; see
  that function's docstring for why it's faster.
- a `score` function that returns `None` to reject a candidate, or a base
  confidence. Validate whatever can be validated: check digits, state codes,
  dates.
- `context` keywords, including Hindi or other Indian-language words where
  people actually use them.
- `requires_context=True` if the bare pattern is common in ordinary text
  (a 6-digit number, a letter followed by 7 digits).

Then add it to `DEFAULT_DETECTORS`, and add tests in `tests/test_detect.py`:
at least one positive case, the main false positive you're guarding against,
and a round trip through `aadhaarguard.fake` if you add a generator.

Run `python scripts/benchmark.py` before and after; a new detector shouldn't
make log scanning much slower.

## Test data

Never commit real personal data, not even your own. Generate values with
`aadhaarguard.fake` or build them in the test from a checksum function.

## UPI handles

To add handles, edit `UPI_HANDLES` in `detectors.py`. Only add handles that
are actually issued by a bank or app.
