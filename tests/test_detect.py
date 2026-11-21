import pytest

from bharatpii import Scanner, scan
from bharatpii.checksums import luhn_digit, verhoeff_digit
from bharatpii.fake import Faker

F = Faker(seed=7)


def kinds(text, **kw):
    return [m.kind for m in scan(text, **kw)]


def bad_check(num: str) -> str:
    """Same number with the last digit changed so the checksum fails."""
    return num[:-1] + str((int(num[-1]) + 1) % 10)


# --- Aadhaar ---------------------------------------------------------------

@pytest.mark.parametrize("sep", [" ", "-", ""])
def test_aadhaar_formats(sep):
    a = F.aadhaar(sep=sep)
    found = scan(f"Aadhaar: {a}")
    assert [m.kind for m in found] == ["aadhaar"]
    assert found[0].value == a
    assert found[0].context


def test_aadhaar_without_keyword_still_found_but_lower():
    a = F.aadhaar()
    with_kw = scan(f"aadhaar {a}")[0].confidence
    without = scan(f"ref {a}")[0].confidence
    assert without < with_kw


def test_aadhaar_hindi_keyword():
    assert scan(f"आधार संख्या {F.aadhaar()}")[0].context


def test_aadhaar_bad_checksum_ignored():
    a = F.aadhaar(sep="")
    assert kinds(f"aadhaar {bad_check(a)}") == []


def test_aadhaar_cannot_start_with_0_or_1():
    body = "1" + "2345678901"
    assert kinds(f"aadhaar {body + verhoeff_digit(body)}") == []


def test_aadhaar_mixed_separators_ignored():
    a = F.aadhaar(sep="")
    assert kinds(f"aadhaar {a[:4]} {a[4:8]}-{a[8:]}") == []


def test_aadhaar_not_matched_inside_longer_number():
    a = F.aadhaar(sep="")
    assert "aadhaar" not in kinds(f"id 9{a}9")


# --- Virtual ID vs card --------------------------------------------------

def test_vid_needs_keyword():
    vid = F.aadhaar_vid()
    assert "aadhaar_vid" in kinds(f"VID {vid}")
    assert "aadhaar_vid" not in kinds(f"number {vid}")


def test_card_luhn():
    card = F.card()
    assert kinds(f"card {card}") == ["card"]
    assert kinds(f"card {bad_check(card.replace(' ', ''))}") == []


def test_card_visa_unseparated():
    body = "4" + "53201487659012"
    assert kinds(body + luhn_digit(body)) == ["card"]


# --- PAN / GSTIN / IFSC --------------------------------------------------

def test_pan():
    assert kinds("PAN: ABCPE1234F") == ["pan"]


def test_ignore_case_option():
    assert kinds("pan abcpe1234f") == []
    s = Scanner(ignore_case=True)
    assert [m.kind for m in s.scan("pan abcpe1234f")] == ["pan"]
    g = F.gstin().lower()
    assert [m.kind for m in s.scan(f"gstin {g}")] == ["gstin"]
    assert s.scan("or 12 1234") == []  # plates stay uppercase-only


def test_pan_holder_type_letter():
    assert kinds("ABCXE1234F") == []  # X is not a valid 4th letter


def test_pan_keyword_boundaries():
    s = Scanner()
    assert scan("PAN ABCPE1234F")[0].context
    assert not scan("company ABCPE1234F")[0].context  # 'pan' inside 'company'
    assert s


def test_gstin_beats_embedded_pan():
    g = F.gstin()
    found = scan(f"GSTIN {g}")
    assert [m.kind for m in found] == ["gstin"]
    assert found[0].value == g


def test_gstin_bad_check_or_state_rejected():
    g = F.gstin()
    wrong = g[:-1] + ("A" if g[-1] != "A" else "B")
    assert kinds(wrong) == []
    assert kinds("45" + g[2:]) == []  # 45 is not a GST state code


def test_ifsc():
    found = scan("IFSC: SBIN0001234")
    assert [m.kind for m in found] == ["ifsc"] and found[0].context
    assert kinds("SBIN1001234") == []  # 5th char must be 0


# --- UPI / email ---------------------------------------------------------

def test_upi_known_handle():
    m = scan("pay ravi.kumar@okaxis")[0]
    assert m.kind == "upi" and m.confidence >= 0.95


def test_upi_unknown_handle_lower_confidence():
    m = scan("send to ravi@someapp")[0]
    assert m.kind == "upi" and m.confidence < 0.7


def test_mobile_number_upi():
    assert kinds("9876543210@ybl") == ["upi"]


def test_email_is_not_upi():
    assert kinds("write to ravi@example.com") == ["email"]
    assert kinds("write to ravi@ybl.co.in.") == ["email"]


def test_upi_at_sentence_end():
    found = scan("My UPI is ravi@ybl.")
    assert [m.value for m in found] == ["ravi@ybl"]


# --- phone ---------------------------------------------------------------

@pytest.mark.parametrize(
    "num",
    ["9876543210", "+91 98765 43210", "+91-9876543210", "+919876543210",
     "09876543210", "98765 43210", "987 654 3210", "0091 9876543210"],
)
def test_phone_formats(num):
    found = scan(f"call {num} now")
    assert [m.kind for m in found] == ["phone"], num
    assert found[0].value == num


def test_phone_prefix_raises_confidence():
    assert scan("+91 9876543210")[0].confidence > scan("9876543210")[0].confidence


@pytest.mark.parametrize("num", ["5876543210", "9999999999", "98765432101"])
def test_not_phone(num):
    assert "phone" not in kinds(num)


# --- vehicles / DL -------------------------------------------------------

@pytest.mark.parametrize("plate", ["MH12AB1234", "MH 12 AB 1234", "KA-01-HH-1234", "DL 3C 1234", "TN 09 Z 9999"])
def test_vehicle(plate):
    assert kinds(plate) == ["vehicle"]


def test_vehicle_needs_uppercase_and_state_code():
    assert kinds("or 12 1234") == []
    assert kinds("XX 12 AB 1234") == []
    assert kinds("MH 12 AB 0000") == []


def test_bh_series():
    assert kinds("22 BH 1234 AA") == ["vehicle"]
    assert kinds("19 BH 1234 AA") == []  # BH series started 2021


def test_driving_licence():
    assert kinds("DL no MH14 20110062821") == ["driving_licence"]
    assert kinds("MH1420110062821") == ["driving_licence"]
    assert kinds("MH14 20990062821") == []  # issue year in the future


# --- keyword-gated kinds -------------------------------------------------

@pytest.mark.parametrize(
    "kind,value,keyword",
    [
        ("passport", "J8369854", "passport no"),
        ("voter_id", "ABC1234567", "voter id"),
        ("bank_account", "123456789012345", "a/c"),
        ("pincode", "560001", "PIN code"),
        ("pincode", "560 001", "pincode"),
    ],
)
def test_keyword_gated(kind, value, keyword):
    assert kinds(f"{keyword}: {value}") == [kind]
    assert kind not in kinds(f"see {value} here")


def test_keyword_after_value():
    assert kinds("560001 (pincode)") == ["pincode"]


# --- scanner behaviour ---------------------------------------------------

def test_matches_sorted_and_non_overlapping():
    text = f"PAN ABCPE1234F, phone 9876543210, GSTIN {F.gstin()}, aadhaar {F.aadhaar()}"
    found = scan(text)
    assert [m.kind for m in found] == ["pan", "phone", "gstin", "aadhaar"]
    for a, b in zip(found, found[1:]):
        assert a.end <= b.start
    for m in found:
        assert text[m.start : m.end] == m.value


def test_kinds_filter():
    text = "PAN ABCPE1234F phone 9876543210"
    assert kinds(text, kinds=["phone"]) == ["phone"]
    with pytest.raises(ValueError):
        Scanner(kinds=["nope"])


def test_min_confidence():
    text = "send to ravi@someapp"
    assert kinds(text) == ["upi"]
    assert kinds(text, min_confidence=0.9) == []


def test_contains_pii():
    s = Scanner()
    assert s.contains_pii("PAN ABCPE1234F")
    assert not s.contains_pii("nothing here")


def test_match_to_dict():
    d = scan("PAN ABCPE1234F")[0].to_dict()
    assert d["kind"] == "pan" and d["value"] == "ABCPE1234F"


BENIGN = """
2024-11-21 10:30:00 INFO request 7f3c9a2e-4b1d-4c8e-9f00-123456789abc took 1234 ms
Price Rs 1,23,456.78 incl. GST @ 18%. Invoice INV-2024-000123, qty 12, SKU AB-1234.
commit 3f2a9c1b7e4d5f60a1b2c3d4e5f60718293a4b5c, version 3.12.10, port 8080
IP 192.168.1.10, ISBN 978-3-16-148410-0, call me @ 5pm, meeting at 10:45, room 404
Order #4521 shipped. Total 2,499. Tracking 1Z999AA10123456784 via carrier.
"""


def test_no_false_positives_on_ordinary_text():
    assert scan(BENIGN) == []


def test_generated_values_round_trip():
    f = Faker(seed=123)
    gens = {
        "aadhaar": lambda: f"aadhaar {f.aadhaar()}",
        "aadhaar_vid": lambda: f"VID {f.aadhaar_vid()}",
        "pan": lambda: f.pan(),
        "gstin": lambda: f.gstin(state=f"{f.r.randint(1, 38):02d}"),
        "phone": lambda: f.phone(),
        "upi": lambda: f.upi(),
        "ifsc": lambda: f"IFSC {f.ifsc()}",
        "card": lambda: f.card(),
        "vehicle": lambda: f.vehicle(),
        "pincode": lambda: f"pincode {f.pincode()}",
    }
    for kind, gen in gens.items():
        for _ in range(200):
            text = gen()
            assert kinds(text) == [kind], text


def test_keyword_beats_lucky_checksum():
    # 50100123456789 passes Luhn by chance; "a/c" says it is an account.
    assert kinds("a/c 50100123456789") == ["bank_account"]
    assert kinds("card 50100123456789") == ["card"]


def test_account_keyword_does_not_steal_phone():
    assert kinds("Account holder Ravi, phone 9876543210") == ["phone"]
