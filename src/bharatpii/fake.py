"""Generate synthetic, checksum-valid identifiers for tests and demos.

A randomly generated Aadhaar, PAN or phone number can still belong to a
real person. Use these only as test fixtures; never publish them as
"sample customer data".

    from bharatpii import fake
    f = fake.Faker(seed=42)
    f.aadhaar()   # 12 digits in groups of 4, Verhoeff-valid
    f.gstin()     # 15 characters with a correct check character
"""

from __future__ import annotations

import random
import string
from typing import Optional

from .checksums import gstin_check_char, luhn_digit, verhoeff_digit
from .detectors import STATE_CODES, UPI_HANDLES

_UP = string.ascii_uppercase


class Faker:
    def __init__(self, seed: Optional[int] = None) -> None:
        self.r = random.Random(seed)

    def _digits(self, n: int) -> str:
        return "".join(self.r.choice(string.digits) for _ in range(n))

    def _letters(self, n: int) -> str:
        return "".join(self.r.choice(_UP) for _ in range(n))

    def aadhaar(self, sep: str = " ") -> str:
        while True:
            body = self.r.choice("23456789") + self._digits(10)
            num = body + verhoeff_digit(body)
            if len(set(num)) > 2:
                break
        return sep.join((num[:4], num[4:8], num[8:]))

    def aadhaar_vid(self, sep: str = " ") -> str:
        body = self.r.choice("123456789") + self._digits(14)
        num = body + verhoeff_digit(body)
        return sep.join(num[i : i + 4] for i in range(0, 16, 4))

    def pan(self, holder: str = "P") -> str:
        return self._letters(3) + holder + self._letters(1) + self._digits(4) + self._letters(1)

    def gstin(self, state: str = "29", pan: Optional[str] = None) -> str:
        first14 = state + (pan or self.pan(self.r.choice("PCF"))) + self.r.choice("123456789") + "Z"
        return first14 + gstin_check_char(first14)

    def phone(self, prefix: str = "+91 ") -> str:
        local = self.r.choice("6789") + self._digits(9)
        return f"{prefix}{local[:5]} {local[5:]}"

    def upi(self, name: Optional[str] = None) -> str:
        name = name or self.r.choice(["ravi", "priya", "arjun", "meera", "kiran"]) + self._digits(2)
        return f"{name}@{self.r.choice(sorted(UPI_HANDLES))}"

    def ifsc(self) -> str:
        return self._letters(4) + "0" + self._digits(6)

    def card(self, prefix: str = "6521") -> str:  # 6521 = RuPay range
        body = prefix + self._digits(15 - len(prefix))
        num = body + luhn_digit(body)
        return " ".join(num[i : i + 4] for i in range(0, 16, 4))

    def vehicle(self) -> str:
        return f"{self.r.choice(STATE_CODES)} {self.r.randint(1, 99):02d} {self._letters(2)} {self.r.randint(1, 9999):04d}"

    def pincode(self) -> str:
        return self.r.choice("12345678") + self._digits(5)


_default = Faker()
aadhaar = _default.aadhaar
aadhaar_vid = _default.aadhaar_vid
pan = _default.pan
gstin = _default.gstin
phone = _default.phone
upi = _default.upi
ifsc = _default.ifsc
card = _default.card
vehicle = _default.vehicle
pincode = _default.pincode
