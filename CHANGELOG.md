# Changelog

## 0.2.0 - 2026-11-21

- Renamed from `bharatpii` to `aadhaarguard` (package, import, CLI command,
  pre-commit hook id). PyPI rejected `bharatpii` as too similar to an existing
  project. 0.1.x was never published on PyPI. No functional changes.

## 0.1.1 - 2026-11-21

- Require Python 3.10+. Python 3.9 is end-of-life and no longer available on
  GitHub's Ubuntu runners, so 3.9 support could not be tested.
- CI: test on 3.10-3.14, update to checkout@v7 and setup-python@v7.

## 0.1.0 - 2026-11-21

First release.

- Detectors: Aadhaar, Aadhaar VID, PAN, GSTIN, IFSC, UPI, email, mobile,
  payment card, bank account, vehicle (incl. BH series), driving licence,
  passport, voter ID, PIN code.
- Checksums: Verhoeff (Aadhaar/VID), Luhn (cards), GSTIN mod-36.
- Keyword context in English and Hindi; keyword-gated detectors for common
  patterns.
- Redaction styles: tag, mask, partial, keyed hash.
- `RedactingFilter` for the `logging` module.
- CLI: `aadhaarguard scan | redact | kinds`, JSON output, masked output by default,
  exit code 1 on findings, pre-commit hook.
- `aadhaarguard.fake` for checksum-valid test fixtures.
