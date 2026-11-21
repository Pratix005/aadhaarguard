"""Check-digit algorithms used by Indian identifiers.

- Verhoeff: Aadhaar (12 digits) and Aadhaar Virtual ID (16 digits).
- Luhn: payment cards (Visa, Mastercard, RuPay, ...).
- GSTIN: base-36 weighted mod-36 check character (15th character).
"""

from __future__ import annotations

_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def verhoeff_valid(number: str) -> bool:
    """True if ``number`` (digits only) ends in a correct Verhoeff check digit."""
    if not number.isdigit():
        return False
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_digit(number: str) -> str:
    """Return the Verhoeff check digit to append to ``number``."""
    if not number.isdigit():
        raise ValueError("digits only")
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[c])


def luhn_valid(number: str) -> bool:
    if not number.isdigit() or len(number) < 2:
        return False
    total = 0
    for i, ch in enumerate(reversed(number)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def luhn_digit(number: str) -> str:
    for d in "0123456789":
        if luhn_valid(number + d):
            return d
    raise ValueError("digits only")  # pragma: no cover


_B36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def gstin_check_char(first14: str) -> str:
    """Return the 15th (check) character for the first 14 characters of a GSTIN."""
    first14 = first14.upper()
    if len(first14) != 14 or any(c not in _B36 for c in first14):
        raise ValueError("need 14 alphanumeric characters")
    total = 0
    for i, ch in enumerate(first14):
        product = _B36.index(ch) * (2 if i % 2 else 1)
        total += product // 36 + product % 36
    return _B36[(36 - total % 36) % 36]


def gstin_valid(gstin: str) -> bool:
    gstin = gstin.upper()
    if len(gstin) != 15:
        return False
    try:
        return gstin_check_char(gstin[:14]) == gstin[14]
    except ValueError:
        return False
