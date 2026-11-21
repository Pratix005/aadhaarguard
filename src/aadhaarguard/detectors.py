"""Built-in detectors.

Each detector is a regex plus a ``score`` function. ``score`` gets the raw
match and returns a confidence in [0, 1], or ``None`` to reject it (for
example when a checksum fails). Detectors with ``requires_context=True``
only fire when one of their keywords appears near the match, because the
pattern alone (a bare 6-digit number, say) is too common to report.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from typing import Callable, Optional, Tuple

from .checksums import gstin_valid, luhn_valid, verhoeff_valid

ScoreFn = Callable[[str], Optional[float]]


@dataclass(frozen=True)
class Detector:
    kind: str
    label: str
    pattern: "re.Pattern[str]"
    score: ScoreFn
    context: Tuple[str, ...] = ()
    requires_context: bool = False
    description: str = ""
    case_insensitive_ok: bool = False  # Scanner(ignore_case=True) may add re.I
    needs: str = ""  # literal that must appear in the text; lets the scanner skip the regex
    _ctx_re: Optional["re.Pattern[str]"] = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.context:
            words = "|".join(re.escape(w) for w in sorted(self.context, key=len, reverse=True))
            object.__setattr__(
                self, "_ctx_re", re.compile(rf"(?<![a-z0-9])(?:{words})(?![a-z0-9])")
            )

    def has_context(self, window: str) -> bool:
        return bool(self._ctx_re and self._ctx_re.search(window.lower()))


def digits(s: str) -> str:
    return "".join(c for c in s if c.isdigit())


def _const(value: float) -> ScoreFn:
    return lambda _raw: value


def _repetitive(d: str) -> bool:
    return len(set(d)) <= 2


# --- state / RTO codes ---------------------------------------------------

STATE_CODES = (
    "AN AP AR AS BR CG CH DD DL DN GA GJ HP HR JH JK KA KL LA LD MH ML MN MP "
    "MZ NL OD OR PB PY RJ SK TN TR TS UK UA UP WB"
).split()
_STATES = "|".join(STATE_CODES)

# GST state codes: 01-38, plus 97 (other territory) and 99 (centre jurisdiction).
GST_STATE_CODES = {f"{i:02d}" for i in range(1, 39)} | {"97", "99"}

# Common UPI handles (PSP suffixes). Not exhaustive: unknown handles are
# still reported, with lower confidence.
UPI_HANDLES = frozenset(
    """
    ybl ibl axl okaxis okhdfcbank okicici oksbi paytm ptyes ptaxis pthdfc ptsbi
    upi apl yapl rapl abfspay axisbank axisb hdfcbank icici sbi kotak kmbl
    idfcbank idfcfirst indus federal fbl rbl aubank yesbank yesbankltd yesg
    barodampay pnb boi unionbankofindia uboi unionbank cnrb canarabank
    ikwik freecharge jupiteraxis slice airtel airtelpaymentsbank jio waaxis
    wahdfcbank waicici wasbi dbs hsbc citi sc kbl kvb cub tmb equitas ujjivan
    mahb centralbank cbin iob indianbank idbi dlb jkb fam superyes naviaxis
    """.split()
)

# Payment card networks that can appear in India: Visa (4), Mastercard (2, 5),
# Amex/Diners/JCB (3), RuPay/Discover (6, 8, 508...).
_CARD_FIRST = set("234568")

_E = r"(?![A-Za-z0-9])"  # right boundary


def _first(cls: str, not_after: str = "[A-Za-z0-9]") -> str:
    """First character class followed by a left-boundary check.

    ``(?<!x)[cls]`` is the obvious way to write a left boundary, but a
    pattern that starts with a lookbehind makes Python's ``re`` try every
    position. Putting the class first lets ``re`` skip ahead to plausible
    start characters, which is 2-3x faster on log-sized input.
    """
    return f"{cls}(?<!{not_after}{cls})"


# --- score functions -----------------------------------------------------


def _score_aadhaar(raw: str) -> Optional[float]:
    d = digits(raw)
    if len(d) != 12 or d[0] in "01" or _repetitive(d) or not verhoeff_valid(d):
        return None
    return 0.75


def _score_vid(raw: str) -> Optional[float]:
    d = digits(raw)
    if len(d) != 16 or _repetitive(d) or not verhoeff_valid(d):
        return None
    return 0.8


def _score_phone(raw: str) -> Optional[float]:
    d = digits(raw)
    prefixed = len(d) > 10
    local = d[-10:]
    if local[0] not in "6789" or _repetitive(local):
        return None
    return 0.9 if prefixed else 0.7


def _score_card(raw: str) -> Optional[float]:
    d = digits(raw)
    if not 13 <= len(d) <= 19 or d[0] not in _CARD_FIRST or _repetitive(d):
        return None
    return 0.9 if luhn_valid(d) else None


def _score_gstin(raw: str) -> Optional[float]:
    g = raw.upper()
    if g[:2] not in GST_STATE_CODES:
        return None
    return 0.98 if gstin_valid(g) else None


def _score_upi(raw: str) -> Optional[float]:
    handle = raw.rsplit("@", 1)[1].lower()
    return 0.95 if handle in UPI_HANDLES else 0.55


def _score_dl(raw: str) -> Optional[float]:
    m = re.search(r"((?:19|20)\d{2})\d{7}$", re.sub(r"[ -]", "", raw))
    if not m or int(m.group(1)) > date.today().year:
        return None
    return 0.85


def _score_bh(raw: str) -> Optional[float]:
    year = int(digits(raw)[:2])
    return 0.9 if year >= 21 else None  # BH series began in 2021


def _score_pan(raw: str) -> Optional[float]:
    return 0.85


# --- the detectors -------------------------------------------------------

AADHAAR = Detector(
    kind="aadhaar",
    label="Aadhaar number",
    pattern=re.compile(_first("[2-9]", r"[\w-]") + r"\d{3}([ -]?)\d{4}\1\d{4}(?!\w|[ -]\d)"),
    score=_score_aadhaar,
    context=("aadhaar", "aadhar", "adhaar", "uid", "uidai", "आधार"),
    description="12 digits, first digit 2-9, Verhoeff checksum",
)

AADHAAR_VID = Detector(
    kind="aadhaar_vid",
    label="Aadhaar Virtual ID",
    pattern=re.compile(_first(r"\d", r"[\w-]") + r"\d{3}([ -]?)\d{4}\1\d{4}\1\d{4}(?!\w|[ -]\d)"),
    score=_score_vid,
    context=("vid", "virtual id", "virtual-id"),
    requires_context=True,
    description="16 digits, Verhoeff checksum; needs a 'VID' keyword nearby",
)

PAN = Detector(
    kind="pan",
    case_insensitive_ok=True,
    label="PAN",
    pattern=re.compile(_first("[A-Z]") + r"[A-Z]{2}[ABCFGHJLPT][A-Z]\d{4}[A-Z]" + _E),
    score=_score_pan,
    context=("pan", "pan card", "permanent account", "पैन"),
    description="AAAAA9999A; 4th letter is the holder type (P = person, C = company, ...)",
)

GSTIN = Detector(
    kind="gstin",
    case_insensitive_ok=True,
    label="GSTIN",
    pattern=re.compile(
        _first(r"\d") + r"\d[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]" + _E
    ),
    score=_score_gstin,
    context=("gst", "gstin", "gst no"),
    description="state code + PAN + entity + Z + mod-36 check character",
)

IFSC = Detector(
    kind="ifsc",
    case_insensitive_ok=True,
    label="IFSC",
    pattern=re.compile(_first("[A-Z]") + r"[A-Z]{3}0[A-Z0-9]{6}" + _E),
    score=_const(0.7),
    context=("ifsc", "ifsc code", "branch"),
    description="4-letter bank code + 0 + 6-character branch code",
)

UPI = Detector(
    kind="upi",
    label="UPI ID",
    pattern=re.compile(
        _first("[A-Za-z0-9]", r"[\w.+-]")
        + r"[A-Za-z0-9._-]{1,254}@[A-Za-z][A-Za-z0-9]{1,63}(?![\w-]|\.[\w-])"
    ),
    score=_score_upi,
    needs="@",
    context=("upi", "vpa", "gpay", "google pay", "phonepe", "paytm", "bhim"),
    description="name@handle; known bank/app handles score higher",
)

EMAIL = Detector(
    kind="email",
    label="Email address",
    pattern=re.compile(
        _first("[A-Za-z0-9_%+-]", r"[\w.+-]")
        + r"[A-Za-z0-9._%+-]*@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w-])"
    ),
    score=_const(0.9),
    needs="@",
    context=("email", "e-mail", "mail"),
    description="standard email address",
)

PHONE = Detector(
    kind="phone",
    label="Indian mobile number",
    pattern=re.compile(
        r"(?=[+\d])(?<![\w+])(?:(?:\+91|0091|91)[ -]?|0)?"
        r"(?:[6-9]\d{4}[ -]?\d{5}|[6-9]\d{2}[ -]\d{3}[ -]\d{4})(?!\w|[ -]\d)"
    ),
    score=_score_phone,
    context=("phone", "mobile", "mob", "ph", "tel", "call", "whatsapp", "contact", "मोबाइल", "फोन"),
    description="10 digits starting 6-9, optional +91 / 0 prefix",
)

CARD = Detector(
    kind="card",
    label="Payment card number",
    pattern=re.compile(_first(r"\d", r"[\d-]") + r"(?:[ -]?\d){12,18}(?!\d)"),
    score=_score_card,
    context=("card", "credit", "debit", "visa", "mastercard", "rupay"),
    description="13-19 digits, Luhn checksum",
)

BANK_ACCOUNT = Detector(
    kind="bank_account",
    label="Bank account number",
    pattern=re.compile(_first(r"\d", r"\d") + r"\d{8,17}(?!\d)"),
    score=_const(0.6),
    context=("account", "a/c", "acct", "ac no", "acc no", "account no", "खाता"),
    requires_context=True,
    description="9-18 digits; needs an 'account' keyword nearby",
)

VEHICLE = Detector(
    kind="vehicle",
    label="Vehicle registration",
    pattern=re.compile(
        _first("[A-Z]") + rf"[A-Z](?<={_STATES})[ -]?(?:0?[1-9]|[1-9]\d)[ -]?(?:[A-Z]{{1,3}}[ -]?)?(?!0000)\d{{4}}" + _E
    ),
    score=_const(0.8),
    context=("vehicle", "car", "bike", "registration", "reg no", "rc", "number plate"),
    description="state code + RTO number + series + 4 digits (uppercase only)",
)

VEHICLE_BH = Detector(
    kind="vehicle",
    label="Vehicle registration (BH series)",
    pattern=re.compile(_first(r"\d") + r"\d[ -]?BH[ -]?(?!0000)\d{4}[ -]?[A-Z]{1,2}" + _E),
    score=_score_bh,
    needs="BH",
    context=VEHICLE.context,
    description="YY BH 9999 AA (Bharat series, 2021+)",
)

DRIVING_LICENCE = Detector(
    kind="driving_licence",
    case_insensitive_ok=True,
    label="Driving licence",
    pattern=re.compile(_first("[A-Z]") + rf"[A-Z](?<={_STATES})[ -]?\d{{2}}[ -]?(?:19|20)\d{{2}}[ -]?\d{{7}}(?!\d)"),
    score=_score_dl,
    context=("driving", "licence", "license", "dl", "dl no"),
    description="state + RTO + year of issue + 7 digits",
)

PASSPORT = Detector(
    kind="passport",
    case_insensitive_ok=True,
    label="Passport number",
    pattern=re.compile(_first("[A-PR-WY]") + r"[1-9]\d{5}[1-9]" + _E),
    score=_const(0.85),
    context=("passport", "पासपोर्ट"),
    requires_context=True,
    description="1 letter + 7 digits; needs a 'passport' keyword nearby",
)

VOTER_ID = Detector(
    kind="voter_id",
    case_insensitive_ok=True,
    label="Voter ID (EPIC)",
    pattern=re.compile(_first("[A-Z]") + r"[A-Z]{2}\d{7}" + _E),
    score=_const(0.85),
    context=("voter", "voter id", "epic", "election"),
    requires_context=True,
    description="3 letters + 7 digits; needs a 'voter'/'EPIC' keyword nearby",
)

PINCODE = Detector(
    kind="pincode",
    label="PIN code",
    pattern=re.compile(_first("[1-9]", r"\d") + r"\d{2} ?\d{3}(?!\d)"),
    score=_const(0.7),
    context=("pin", "pincode", "pin code", "postal", "postal code", "zip"),
    requires_context=True,
    description="6 digits; needs a 'PIN'/'pincode' keyword nearby",
)

# Order matters only for ties (same span, same confidence): earlier wins.
DEFAULT_DETECTORS: Tuple[Detector, ...] = (
    GSTIN,
    AADHAAR,
    AADHAAR_VID,
    CARD,
    PAN,
    PHONE,
    UPI,
    EMAIL,
    IFSC,
    DRIVING_LICENCE,
    VEHICLE_BH,
    VEHICLE,
    PASSPORT,
    VOTER_ID,
    BANK_ACCOUNT,
    PINCODE,
)

KINDS = tuple(dict.fromkeys(d.kind for d in DEFAULT_DETECTORS))
